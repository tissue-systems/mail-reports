//! DMARC failure reports (RFC 6591 / RFC 9991): a `multipart/report;
//! report-type=feedback-report` with a `message/feedback-report` part and the
//! reported message, whole (`message/rfc822`) or headers only
//! (`text/rfc822-headers`). Only the reported message's header block is
//! kept, cut at a line break to [`Limits::max_ruf_header_bytes`], and never
//! a body part.
//!
//! A failure report is read as part of a whole message, so it is parsed
//! through [`parse_message`](crate::parse_message); this module holds the
//! type and the header cut.

use mail_parser::{Message, PartKind};
use serde::Serialize;

use crate::message::content_type;
use crate::{InvalidReport, Limits};

/// One failure report: the feedback fields and the reported headers.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct FailureReport {
    /// The first `Reported-Domain`, or the reported message's From domain when there is none. Lowercased.
    pub domain: String,
    /// `Source-IP`.
    pub source_ip: String,
    /// `Auth-Failure`, such as `dmarc`, `dkim` or `spf`, lowercased.
    pub auth_failure: String,
    /// `Feedback-Type`, normally `auth-failure`, lowercased.
    pub feedback_type: String,
    /// Every `Reported-Domain`, joined with `, `, lowercased.
    pub reported_domain: String,
    /// `Original-Mail-From`.
    pub original_mail_from: String,
    /// Every `Original-Rcpt-To`, joined with `, `.
    pub original_rcpt_to: String,
    /// `Arrival-Date`, as written.
    pub arrival_date: String,
    /// The reported message's header block, cut at a line break to the header cap.
    pub headers: String,
}

/// Reads the report out of `message`, whose root part is the
/// `multipart/report`. Returns the normalised report and the bytes kept as
/// the original: the feedback part, a blank line, then the header block.
pub(crate) fn parse(message: &Message<'_>, limits: &Limits) -> Result<(FailureReport, Vec<u8>), InvalidReport> {
    let mut feedback: Option<Vec<u8>> = None;
    let mut headers: Option<Vec<u8>> = None;
    for part in message.root_part().children() {
        match content_type(part).as_str() {
            "message/feedback-report" if feedback.is_none() => feedback = Some(part.decoded().into_owned()),
            "message/rfc822" | "message/global" if headers.is_none() => {
                headers = Some(match part.kind() {
                    PartKind::Message(nested) => nested.root_part().raw_headers().to_vec(),
                    // A reported message the parser didn't open is one
                    // blob; its header block is everything up to the first
                    // blank line.
                    _ => header_block(&part.decoded()).to_vec(),
                });
            }
            "text/rfc822-headers" | "message/global-headers" if headers.is_none() => {
                headers = Some(header_block(&part.decoded()).to_vec())
            }
            _ => {}
        }
    }
    let feedback = feedback.ok_or_else(|| InvalidReport::new("failure report has no message/feedback-report part"))?;
    let headers = truncate_headers(&headers.unwrap_or_default(), limits.max_ruf_header_bytes);
    let fields = fields(&String::from_utf8_lossy(&feedback));
    let get = |name: &str| -> String {
        fields
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let reported_domain = get("Reported-Domain").to_ascii_lowercase();
    let domain = if !reported_domain.is_empty() {
        reported_domain.split(',').next().unwrap_or("").trim().to_string()
    } else {
        from_domain(&headers).unwrap_or_default()
    };
    if domain.is_empty() {
        return Err("failure report names no domain".into());
    }
    let report = FailureReport {
        domain,
        source_ip: get("Source-IP"),
        auth_failure: get("Auth-Failure").to_ascii_lowercase(),
        feedback_type: get("Feedback-Type").to_ascii_lowercase(),
        reported_domain,
        original_mail_from: get("Original-Mail-From"),
        original_rcpt_to: get("Original-Rcpt-To"),
        arrival_date: get("Arrival-Date"),
        headers,
    };
    let mut raw = feedback;
    if !raw.ends_with(b"\n") {
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(report.headers.as_bytes());
    Ok((report, raw))
}

/// Everything before the first blank line, or all of it when there is none.
/// The line break that ends the last header stays in.
fn header_block(data: &[u8]) -> &[u8] {
    let end = (0..data.len()).find(|&i| data[i] == b'\n' && matches!(data[i + 1..], [b'\n', ..] | [b'\r', b'\n', ..]));
    match end {
        Some(i) => &data[..=i],
        None => data,
    }
}

/// The header block as text, cut at the last line break that fits in `max`
/// bytes.
pub fn truncate_headers(headers: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(headers);
    let text = text.trim_end_matches(['\r', '\n']);
    if text.len() <= max {
        return text.to_string();
    }
    let mut cut = max;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let head = &text[..cut];
    match head.rfind('\n') {
        Some(i) => head[..i].trim_end_matches('\r').to_string(),
        None => head.to_string(),
    }
}

/// `Name: value` lines with folded continuations joined.
fn fields(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = out.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
        } else if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    out
}

/// The domain of the first address in the reported message's From field.
fn from_domain(headers: &str) -> Option<String> {
    let from = fields(headers).into_iter().find(|(n, _)| n.eq_ignore_ascii_case("From"))?.1;
    let addr = match (from.rfind('<'), from.rfind('>')) {
        (Some(a), Some(b)) if a < b => &from[a + 1..b],
        _ => from.as_str(),
    };
    let domain = addr.rsplit_once('@')?.1.trim().trim_end_matches('>').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_block_stops_at_blank_line() {
        assert_eq!(header_block(b"A: 1\r\nB: 2\r\n\r\nbody"), b"A: 1\r\nB: 2\r\n");
        assert_eq!(header_block(b"A: 1\nB: 2\n\nbody"), b"A: 1\nB: 2\n");
        assert_eq!(header_block(b"A: 1\r\n"), b"A: 1\r\n");
    }

    #[test]
    fn long_headers_are_cut_at_a_line() {
        let line = format!("X-Filler: {}\r\n", "a".repeat(100));
        let block = line.repeat(400);
        let cut = truncate_headers(block.as_bytes(), 16 * 1024);
        assert!(cut.len() <= 16 * 1024);
        assert!(cut.ends_with(&"a".repeat(100)));
    }

    #[test]
    fn from_domain_reads_angle_and_bare_forms() {
        assert_eq!(from_domain("From: Ann <ann@Example.com>\r\n").as_deref(), Some("example.com"));
        assert_eq!(from_domain("Subject: x\r\nFrom: ann@example.org\r\n").as_deref(), Some("example.org"));
        assert_eq!(from_domain("Subject: x\r\n"), None);
    }
}
