//! From a raw message to a parsed report: MIME structure with mail-parser,
//! the report part found by content type and file name, unpacked and parsed
//! inside the caps.
//!
//! A message with too many boundary-looking lines is refused before it's
//! parsed. mail-parser is told to stop one part past the part cap, so a
//! message over it is refused rather than half read, and parts deeper than
//! the depth cap are never looked at.

use std::time::Instant;

use mail_parser::{Message, MessageParser, MessagePart};
use serde::Serialize;
use serde_json::Value;

use crate::limits::size;
use crate::{dmarc, ruf, tlsrpt, unpack, Body, Error, InvalidReport, Kind, Limits, Report};

/// `type/subtype`, lowercased, or empty when the part has no Content-Type.
pub(crate) fn content_type(part: MessagePart<'_>) -> String {
    match part.content_type() {
        Some(ct) => match ct.subtype() {
            Some(sub) => format!("{}/{}", ct.ctype(), sub).to_ascii_lowercase(),
            None => ct.ctype().to_ascii_lowercase(),
        },
        None => String::new(),
    }
}

fn is_feedback_report(part: MessagePart<'_>) -> bool {
    content_type(part) == "multipart/report"
        && part
            .content_type()
            .and_then(|ct| ct.attribute("report-type"))
            .is_some_and(|t| t.eq_ignore_ascii_case("feedback-report"))
}

/// What a non-multipart part holds, judged by its content type and then by
/// its file name. Never [`Kind::Ruf`]: a failure report is a whole message,
/// not an attachment.
pub fn classify_part(ctype: &str, filename: &str) -> Option<Kind> {
    let filename = filename.to_ascii_lowercase();
    match ctype.to_ascii_lowercase().as_str() {
        "application/tlsrpt+gzip" | "application/tlsrpt+json" => return Some(Kind::Tlsrpt),
        "application/zip"
        | "application/x-zip-compressed"
        | "application/gzip"
        | "application/x-gzip"
        | "text/xml"
        | "application/xml" => return Some(Kind::Dmarc),
        _ => {}
    }
    if filename.ends_with(".json") || filename.ends_with(".json.gz") {
        return Some(Kind::Tlsrpt);
    }
    if filename.ends_with(".xml") || filename.ends_with(".xml.gz") || filename.ends_with(".zip") {
        return Some(Kind::Dmarc);
    }
    None
}

/// The leaf parts of `message` in document order, down to `max_depth`
/// levels (the root part is level 1). Multiparts are opened; attached
/// messages are leaves and never opened.
fn leaves<'m>(message: &'m Message<'_>, max_depth: usize) -> Vec<MessagePart<'m>> {
    fn walk<'m>(part: MessagePart<'m>, depth: usize, max: usize, out: &mut Vec<MessagePart<'m>>) {
        if !part.is_multipart() {
            out.push(part);
        } else if depth < max {
            for child in part.children() {
                walk(child, depth + 1, max, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(message.root_part(), 1, max_depth, &mut out);
    out
}

pub(crate) fn parse_message(raw: &[u8], limits: &Limits, deadline: Instant) -> Result<Report, Error> {
    let boundary_lines = raw.split(|b| *b == b'\n').filter(|line| line.starts_with(b"--")).count();
    if boundary_lines > limits.max_boundary_lines {
        return Err(Error::Malformed("too many MIME parts".into()));
    }
    let message =
        MessageParser::new().max_parts(limits.max_mime_parts.saturating_add(1)).parse(raw).ok_or(Error::NoReport)?;
    if message.parts().len() > limits.max_mime_parts {
        return Err(Error::Malformed("too many MIME parts".into()));
    }
    let header_from = message
        .from()
        .and_then(|list| list.first())
        .and_then(|mailbox| mailbox.address())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if is_feedback_report(message.root_part()) {
        let invalid = |e| Error::Invalid(Kind::Ruf, e);
        let (report, original) = ruf::parse(&message, limits).map_err(invalid)?;
        check_fields(&report, limits).map_err(invalid)?;
        return Ok(Report { body: Body::Ruf(report), original, header_from });
    }

    for part in leaves(&message, limits.max_mime_depth) {
        if part.is_message() {
            continue;
        }
        let Some(kind) = classify_part(&content_type(part), part.attachment_name().unwrap_or("")) else {
            continue;
        };
        let invalid = |e| Error::Invalid(kind, e);
        let original = unpack::unpack(&part.decoded(), limits.max_unpacked_bytes)
            .map_err(|e| invalid(InvalidReport::new(e.to_string())))?;
        if Instant::now() > deadline {
            return Err(invalid("report took too long to parse".into()));
        }
        let body = match kind {
            Kind::Dmarc => Body::Dmarc(dmarc::parse(&original, limits, deadline).map_err(invalid)?),
            Kind::Tlsrpt => Body::Tlsrpt(tlsrpt::parse(&original, limits).map_err(invalid)?),
            Kind::Ruf => unreachable!("classify_part never returns Ruf"),
        };
        check_fields(&body, limits).map_err(invalid)?;
        return Ok(Report { body, original, header_from });
    }
    Err(Error::NoReport)
}

/// Serialises a report and checks every string in it against the field cap.
/// The aggregate parser caps fields as it reads; this catches the TLS and
/// failure report fields, which arrive whole.
pub(crate) fn check_fields(report: &impl Serialize, limits: &Limits) -> Result<(), InvalidReport> {
    fn walk(value: &Value, max: usize) -> Result<(), InvalidReport> {
        match value {
            Value::String(s) if s.len() > max => {
                Err(format!("a report field is longer than {}", size(max as u64)).into())
            }
            Value::Array(items) => items.iter().try_for_each(|v| walk(v, max)),
            Value::Object(map) => map.values().try_for_each(|v| walk(v, max)),
            _ => Ok(()),
        }
    }
    let value = serde_json::to_value(report).map_err(|e| InvalidReport::new(e.to_string()))?;
    walk(&value, limits.max_field_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn soon() -> Instant {
        Instant::now() + std::time::Duration::from_secs(5)
    }

    #[test]
    fn classification_by_type_and_name() {
        assert_eq!(classify_part("application/gzip", ""), Some(Kind::Dmarc));
        assert_eq!(classify_part("text/xml", ""), Some(Kind::Dmarc));
        assert_eq!(classify_part("application/octet-stream", "google.com!example.com!1!2.xml.gz"), Some(Kind::Dmarc));
        assert_eq!(classify_part("application/octet-stream", "report.ZIP"), Some(Kind::Dmarc));
        assert_eq!(classify_part("application/tlsrpt+gzip", "x.json.gz"), Some(Kind::Tlsrpt));
        assert_eq!(classify_part("application/octet-stream", "x.json"), Some(Kind::Tlsrpt));
        assert_eq!(classify_part("text/plain", ""), None);
        assert_eq!(classify_part("text/html", "index.html"), None);
    }

    #[test]
    fn many_boundaries_are_refused_before_parsing() {
        let raw = format!("From: a@example.com\r\n\r\n{}", "--x\r\n".repeat(300));
        let got = parse_message(raw.as_bytes(), &Limits::DEFAULT, soon());
        assert!(matches!(got, Err(Error::Malformed(_))));
    }

    #[test]
    fn too_many_parts_are_refused() {
        // 70 parts is under the boundary-line cap but over the part cap.
        let parts = "--b\r\nContent-Type: text/plain\r\n\r\nx\r\n".repeat(70);
        let raw =
            format!("From: a@example.com\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n{parts}--b--\r\n");
        let got = parse_message(raw.as_bytes(), &Limits::DEFAULT, soon());
        assert!(matches!(got, Err(Error::Malformed(_))), "{got:?}");
    }

    #[test]
    fn a_message_without_a_report_is_no_report() {
        let raw = b"From: a@example.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\nhello\r\n";
        assert_eq!(parse_message(raw, &Limits::DEFAULT, soon()).unwrap_err(), Error::NoReport);
    }

    #[test]
    fn nesting_past_the_cap_is_not_searched() {
        // Five levels of multipart/mixed around an XML attachment put it at
        // level 6, past the four levels that are searched.
        let mut body = String::from(
            "Content-Type: text/xml\r\n\r\n<feedback><report_metadata><report_id>1</report_id></report_metadata>\
             <policy_published><domain>example.com</domain></policy_published></feedback>\r\n",
        );
        for level in 0..5 {
            body = format!(
                "Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n{body}--b{level}--\r\n"
            );
        }
        let raw = format!("From: a@example.com\r\n{body}");
        let got = parse_message(raw.as_bytes(), &Limits::DEFAULT, soon());
        assert_eq!(got.unwrap_err(), Error::NoReport);

        // The same attachment two levels down is found.
        let mut body = String::from(
            "Content-Type: text/xml\r\n\r\n<feedback><report_metadata><report_id>1</report_id></report_metadata>\
             <policy_published><domain>example.com</domain></policy_published></feedback>\r\n",
        );
        for level in 0..2 {
            body = format!(
                "Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n{body}--b{level}--\r\n"
            );
        }
        let raw = format!("From: a@example.com\r\n{body}");
        let got = parse_message(raw.as_bytes(), &Limits::DEFAULT, soon()).unwrap();
        assert_eq!(got.kind(), Kind::Dmarc);
        assert_eq!(got.header_from, "a@example.com");
    }
}
