//! DMARC aggregate reports (RFC 7489 appendix C, RFC 9990), read with
//! quick-xml's event reader.
//!
//! The parser walks the events once, keeping the path of element names, and
//! fills in the fields it knows; every other element is skipped. Namespace
//! prefixes are ignored, only local names count. quick-xml never expands an
//! entity a document declares: the five predefined ones and character
//! references are resolved here, and any other reference fails the parse.
//! The record cap is checked as each `<record>` opens, the DKIM and SPF
//! result cap as each result opens, and the deadline every 256 events, so
//! none of them waits for the end of the document. Elements nested deeper
//! than [`MAX_DEPTH`] fail the parse.

use std::time::Instant;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use serde::Serialize;

use crate::limits::size;
use crate::{InvalidReport, Limits};

/// One aggregate report.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Aggregate {
    /// `policy_published/domain`, lowercased.
    pub domain: String,
    /// The reporting organisation, `report_metadata/org_name`.
    pub org_name: String,
    /// `report_metadata/email`.
    pub org_email: String,
    /// `report_metadata/report_id`, unique per reporter.
    pub report_id: String,
    /// Start of the reporting period, Unix seconds.
    pub date_begin: i64,
    /// End of the reporting period, Unix seconds.
    pub date_end: i64,
    /// The published policy.
    pub policy: Policy,
    /// Every record, in document order.
    pub records: Vec<Record>,
}

/// The DMARC record the reporter found for the domain.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Policy {
    /// `none`, `quarantine` or `reject`.
    pub p: String,
    /// The subdomain policy; `p` when the report leaves it out.
    pub sp: String,
    /// Percentage of mail the policy applies to; 100 when left out.
    pub pct: u32,
    /// DKIM alignment, `r` or `s`; `r` when left out.
    pub adkim: String,
    /// SPF alignment, `r` or `s`; `r` when left out.
    pub aspf: String,
}

impl Default for Policy {
    /// RFC 7489's defaults for whatever the report leaves out. `sp` falls
    /// back to `p` once the whole document is read.
    fn default() -> Self {
        Policy { p: String::new(), sp: String::new(), pct: 100, adkim: "r".into(), aspf: "r".into() }
    }
}

/// One `<record>`: a source address and what happened to its mail.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Record {
    /// The sending address, as written.
    pub source_ip: String,
    /// Messages from that address in the period.
    pub count: u64,
    /// What the receiver did: `none`, `quarantine` or `reject`.
    pub disposition: String,
    /// Whether DKIM passed aligned, from `policy_evaluated`.
    pub dkim_aligned: bool,
    /// Whether SPF passed aligned, from `policy_evaluated`.
    pub spf_aligned: bool,
    /// The From domain of the messages, lowercased.
    pub header_from: String,
    /// The envelope sender domain, lowercased, when reported.
    pub envelope_from: String,
    /// Each DKIM signature checked.
    pub dkim: Vec<DkimAuth>,
    /// Each SPF check run.
    pub spf: Vec<SpfAuth>,
}

/// One DKIM signature the reporter checked.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct DkimAuth {
    /// The `d=` domain, lowercased.
    pub domain: String,
    /// The `s=` selector, when reported.
    pub selector: String,
    /// `pass`, `fail`, `none` and so on, lowercased.
    pub result: String,
}

/// One SPF check the reporter ran.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SpfAuth {
    /// The domain checked, lowercased.
    pub domain: String,
    /// `pass`, `fail`, `softfail` and so on, lowercased.
    pub result: String,
}

/// How deep elements may nest. The deepest element in the schema is at level
/// five (`feedback/record/row/policy_evaluated/reason`); the path of open
/// elements is kept in memory, so it has to end somewhere.
pub const MAX_DEPTH: usize = 32;

/// Parses one aggregate report file, already unpacked. Strings that name a
/// domain, a policy or a result are lowercased; the rest are kept as sent.
///
/// The deadline is checked every 256 XML events.
pub fn parse(xml: &[u8], limits: &Limits, deadline: Instant) -> Result<Aggregate, InvalidReport> {
    let text = std::str::from_utf8(xml).map_err(|_| InvalidReport::new("report XML is not UTF-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);

    let mut report = Aggregate::default();
    let mut path: Vec<String> = Vec::new();
    let mut buf = String::new();
    let mut saw_feedback = false;
    let mut auth_results = 0usize;
    let mut events = 0u32;

    loop {
        events = events.wrapping_add(1);
        if events.is_multiple_of(256) && Instant::now() > deadline {
            return Err("report took too long to parse".into());
        }
        let event = reader.read_event().map_err(|e| InvalidReport::new(format!("report XML: {e}")))?;
        match event {
            Event::Start(e) => {
                if path.len() >= MAX_DEPTH {
                    return Err(format!("report XML is nested more than {MAX_DEPTH} levels deep").into());
                }
                path.push(element_name(&e));
                buf.clear();
                open(&path, &mut report, &mut saw_feedback, &mut auth_results, limits)?;
            }
            Event::Empty(e) => {
                path.push(element_name(&e));
                buf.clear();
                open(&path, &mut report, &mut saw_feedback, &mut auth_results, limits)?;
                close(&path, "", &mut report)?;
                path.pop();
            }
            Event::End(_) => {
                close(&path, buf.trim(), &mut report)?;
                buf.clear();
                path.pop();
            }
            Event::Text(t) => push(&mut buf, &t.xml10_content(), limits)?,
            Event::CData(t) => push(&mut buf, &t.into_inner(), limits)?,
            Event::GeneralRef(r) => {
                let ch = match r.resolve_char_ref().map_err(|e| InvalidReport::new(format!("report XML: {e}")))? {
                    Some(ch) => ch,
                    None => match &*r {
                        "lt" => '<',
                        "gt" => '>',
                        "amp" => '&',
                        "apos" => '\'',
                        "quot" => '"',
                        other => return Err(format!("report XML uses an undeclared entity &{other};").into()),
                    },
                };
                let mut tmp = [0u8; 4];
                push(&mut buf, ch.encode_utf8(&mut tmp), limits)?;
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if !saw_feedback {
        return Err("not a DMARC aggregate report (no <feedback>)".into());
    }
    if report.domain.is_empty() {
        return Err("report has no policy_published domain".into());
    }
    if report.report_id.is_empty() {
        return Err("report has no report_id".into());
    }
    if report.policy.sp.is_empty() {
        report.policy.sp = report.policy.p.clone();
    }
    Ok(report)
}

/// The element's local name, lowercased.
fn element_name(e: &BytesStart<'_>) -> String {
    e.local_name().as_ref().to_ascii_lowercase()
}

fn push(buf: &mut String, text: &str, limits: &Limits) -> Result<(), InvalidReport> {
    if buf.len() + text.len() > limits.max_field_bytes {
        return Err(format!("a report field is longer than {}", size(limits.max_field_bytes as u64)).into());
    }
    buf.push_str(text);
    Ok(())
}

/// The path below `<feedback>`, joined with `/`, or `None` outside it.
fn rel(path: &[String]) -> Option<String> {
    match path.first().map(String::as_str) {
        Some("feedback") => Some(path[1..].join("/")),
        _ => None,
    }
}

fn open(
    path: &[String],
    report: &mut Aggregate,
    saw_feedback: &mut bool,
    auth_results: &mut usize,
    limits: &Limits,
) -> Result<(), InvalidReport> {
    if path.len() == 1 && path[0] == "feedback" {
        *saw_feedback = true;
        return Ok(());
    }
    let Some(rel) = rel(path) else { return Ok(()) };
    match rel.as_str() {
        "record" => {
            if report.records.len() >= limits.max_records {
                return Err(format!("report has more than {} records", limits.max_records).into());
            }
            report.records.push(Record::default());
        }
        "record/auth_results/dkim" => {
            if let Some(r) = report.records.last_mut() {
                count_auth_result(auth_results, limits)?;
                r.dkim.push(DkimAuth::default());
            }
        }
        "record/auth_results/spf" => {
            if let Some(r) = report.records.last_mut() {
                count_auth_result(auth_results, limits)?;
                r.spf.push(SpfAuth::default());
            }
        }
        _ => {}
    }
    Ok(())
}

fn count_auth_result(seen: &mut usize, limits: &Limits) -> Result<(), InvalidReport> {
    if *seen >= limits.max_auth_results {
        return Err(format!("report has more than {} DKIM and SPF results", limits.max_auth_results).into());
    }
    *seen += 1;
    Ok(())
}

fn close(path: &[String], text: &str, report: &mut Aggregate) -> Result<(), InvalidReport> {
    let Some(rel) = rel(path) else { return Ok(()) };
    let s = || text.to_string();
    let lower = || text.to_ascii_lowercase();
    match rel.as_str() {
        "report_metadata/org_name" => report.org_name = s(),
        "report_metadata/email" => report.org_email = s(),
        "report_metadata/report_id" => report.report_id = s(),
        "report_metadata/date_range/begin" => report.date_begin = number(text, "date_range begin")?,
        "report_metadata/date_range/end" => report.date_end = number(text, "date_range end")?,
        "policy_published/domain" => report.domain = lower(),
        "policy_published/p" => report.policy.p = lower(),
        "policy_published/sp" => report.policy.sp = lower(),
        "policy_published/pct" => report.policy.pct = number(text, "pct")?,
        "policy_published/adkim" => report.policy.adkim = lower(),
        "policy_published/aspf" => report.policy.aspf = lower(),
        _ => {
            let Some(r) = report.records.last_mut() else { return Ok(()) };
            match rel.as_str() {
                "record/row/source_ip" => r.source_ip = s(),
                "record/row/count" => r.count = number(text, "count")?,
                "record/row/policy_evaluated/disposition" => r.disposition = lower(),
                "record/row/policy_evaluated/dkim" => r.dkim_aligned = text.eq_ignore_ascii_case("pass"),
                "record/row/policy_evaluated/spf" => r.spf_aligned = text.eq_ignore_ascii_case("pass"),
                "record/identifiers/header_from" => r.header_from = lower(),
                "record/identifiers/envelope_from" => r.envelope_from = lower(),
                "record/auth_results/dkim/domain" => set_last(&mut r.dkim, |d| d.domain = lower()),
                "record/auth_results/dkim/selector" => set_last(&mut r.dkim, |d| d.selector = s()),
                "record/auth_results/dkim/result" => set_last(&mut r.dkim, |d| d.result = lower()),
                "record/auth_results/spf/domain" => set_last(&mut r.spf, |d| d.domain = lower()),
                "record/auth_results/spf/result" => set_last(&mut r.spf, |d| d.result = lower()),
                _ => {}
            }
        }
    }
    Ok(())
}

fn set_last<T>(list: &mut [T], f: impl FnOnce(&mut T)) {
    if let Some(last) = list.last_mut() {
        f(last);
    }
}

fn number<T: std::str::FromStr>(text: &str, what: &str) -> Result<T, InvalidReport> {
    text.trim().parse().map_err(|_| format!("report {what} is not a number: {text:.40}").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn minimal_report_parses_with_defaults() {
        let xml = br#"<?xml version="1.0"?><feedback><report_metadata><org_name>x</org_name>
            <report_id>1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata>
            <policy_published><domain>Example.COM</domain><p>reject</p></policy_published></feedback>"#;
        let r = parse(xml, &Limits::DEFAULT, soon()).unwrap();
        assert_eq!(r.domain, "example.com");
        assert_eq!(
            r.policy,
            Policy { p: "reject".into(), sp: "reject".into(), pct: 100, adkim: "r".into(), aspf: "r".into() }
        );
        assert!(r.records.is_empty());
    }

    #[test]
    fn namespaced_rfc9990_report_parses() {
        let xml = br#"<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0"><version>1.0</version>
            <report_metadata><org_name>Mail &amp; Co</org_name><report_id>&#x41;BC</report_id>
            <date_range><begin>10</begin><end>20</end></date_range></report_metadata>
            <policy_published><domain>example.com</domain><p>none</p><np>none</np></policy_published>
            <record><row><source_ip>192.0.2.1</source_ip><count>3</count>
            <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated></row>
            <identifiers><header_from>example.com</header_from></identifiers>
            <auth_results><spf><domain>example.com</domain><scope>mfrom</scope><result>pass</result></spf></auth_results>
            </record></feedback>"#;
        let r = parse(xml, &Limits::DEFAULT, soon()).unwrap();
        assert_eq!(r.org_name, "Mail & Co");
        assert_eq!(r.report_id, "ABC");
        assert_eq!(r.records.len(), 1);
        assert!(r.records[0].spf_aligned && !r.records[0].dkim_aligned);
        assert_eq!(r.records[0].spf, vec![SpfAuth { domain: "example.com".into(), result: "pass".into() }]);
    }

    #[test]
    fn undeclared_entity_fails() {
        let xml = br#"<!DOCTYPE feedback [<!ENTITY lol "lol">]><feedback><report_metadata><org_name>&lol;</org_name>
            </report_metadata></feedback>"#;
        assert!(parse(xml, &Limits::DEFAULT, soon()).unwrap_err().as_str().contains("entity"));
    }

    #[test]
    fn too_many_records_fails_early() {
        let mut xml = String::from("<feedback><policy_published><domain>example.com</domain></policy_published>");
        for _ in 0..=Limits::DEFAULT.max_records {
            xml.push_str("<record><row><count>1</count></row></record>");
        }
        xml.push_str("</feedback>");
        assert!(parse(xml.as_bytes(), &Limits::DEFAULT, soon()).unwrap_err().as_str().contains("records"));
    }

    #[test]
    fn long_field_fails() {
        let xml = format!(
            "<feedback><report_metadata><org_name>{}</org_name></report_metadata></feedback>",
            "a".repeat(Limits::DEFAULT.max_field_bytes + 1)
        );
        assert!(parse(xml.as_bytes(), &Limits::DEFAULT, soon()).unwrap_err().as_str().contains("64 KiB"));
    }

    #[test]
    fn not_a_report_fails() {
        assert!(parse(b"<html><body/></html>", &Limits::DEFAULT, soon()).is_err());
        assert!(parse(b"not xml at all <<<", &Limits::DEFAULT, soon()).is_err());
    }

    #[test]
    fn past_deadline_fails() {
        let mut xml = String::from("<feedback>");
        for _ in 0..1000 {
            xml.push_str("<x/>");
        }
        xml.push_str("</feedback>");
        let past = Instant::now() - Duration::from_secs(1);
        assert!(parse(xml.as_bytes(), &Limits::DEFAULT, past).unwrap_err().as_str().contains("too long"));
    }
}
