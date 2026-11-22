//! The report parsers against realistic reporter output.

use std::time::{Duration, Instant};

use mail_reports::{dmarc, parse_message, tlsrpt, Body, Error, Kind, Limits};
use serde_json::Value;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[test]
fn google_aggregate_matches_expected_json() {
    let xml = include_bytes!("fixtures/google-aggregate.xml");
    let expected: Value = serde_json::from_str(include_str!("fixtures/google-aggregate.json")).unwrap();
    let got = serde_json::to_value(dmarc::parse(xml, &Limits::DEFAULT, deadline()).unwrap()).unwrap();
    assert_eq!(got, expected);
}

#[test]
fn microsoft_tlsrpt_normalises() {
    let report = tlsrpt::parse(include_bytes!("fixtures/microsoft-tlsrpt.json"), &Limits::DEFAULT).unwrap();
    let got = serde_json::to_value(&report).unwrap();
    let expected = serde_json::json!({
        "domain": "example.com",
        "org_name": "Microsoft Corporation",
        "report_id": "133771234567890123+example.com",
        "date_begin": 1794787200,
        "date_end": 1794873599,
        "policies": [{
            "type": "sts",
            "domain": "example.com",
            "mx_host": ["mx1.example.com"],
            "success": 211,
            "failure": 3,
            "failures": [{
                "result_type": "certificate-expired",
                "sending_ip": "203.0.113.20",
                "receiving_mx": "mx1.example.com",
                "count": 3
            }]
        }]
    });
    assert_eq!(got, expected);
}

#[test]
fn a_field_over_64_kib_is_refused() {
    let long = "a".repeat(70 * 1024);
    let xml = format!(
        "<feedback><report_metadata><org_name>x</org_name><report_id>1</report_id>\
         <extra_contact_info>{long}</extra_contact_info></report_metadata>\
         <policy_published><domain>example.com</domain></policy_published></feedback>"
    );
    assert!(dmarc::parse(xml.as_bytes(), &Limits::DEFAULT, deadline()).is_err());
}

#[test]
fn more_than_ten_thousand_records_is_refused() {
    let record = "<record><row><source_ip>192.0.2.1</source_ip><count>1</count></row></record>";
    let xml = format!(
        "<feedback><report_metadata><report_id>1</report_id></report_metadata>\
         <policy_published><domain>example.com</domain></policy_published>{}</feedback>",
        record.repeat(10_001)
    );
    let err = dmarc::parse(xml.as_bytes(), &Limits::DEFAULT, deadline()).unwrap_err();
    assert!(err.as_str().contains("10000"), "{err}");
}

#[test]
fn gzipped_tlsrpt_attachment_is_found() {
    use std::io::Write;
    let json = include_bytes!("fixtures/microsoft-tlsrpt.json");
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(json).unwrap();
    let gz = enc.finish().unwrap();
    let b64 = base64_lines(&gz);
    let raw = format!(
        "From: TLSRPT <tlsrpt-noreply@microsoft.com>\r\n\
         Subject: Report Domain: example.com\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=tlsrpt; boundary=\"b\"\r\n\
         \r\n\
         --b\r\nContent-Type: text/plain\r\n\r\nThis is a TLS report.\r\n\
         --b\r\nContent-Type: application/tlsrpt+gzip\r\n\
         Content-Disposition: attachment; filename=\"microsoft.com!example.com!1!2.json.gz\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--b--\r\n"
    );
    let report = parse_message(raw.as_bytes(), &Limits::DEFAULT, deadline()).unwrap();
    assert_eq!(report.kind(), Kind::Tlsrpt);
    assert_eq!(report.body.domain(), "example.com");
    assert_eq!(report.header_from, "tlsrpt-noreply@microsoft.com");
    assert_eq!(report.original, json);
}

#[test]
fn failure_report_keeps_headers_only() {
    let raw = "From: dmarc@reporter.example\r\n\
        Content-Type: multipart/report; report-type=feedback-report; boundary=\"r\"\r\n\
        \r\n\
        --r\r\nContent-Type: text/plain\r\n\r\nA message failed DMARC.\r\n\
        --r\r\nContent-Type: message/feedback-report\r\n\r\n\
        Feedback-Type: auth-failure\r\nAuth-Failure: dmarc\r\n\
        Source-IP: 192.0.2.7\r\nReported-Domain: Example.com\r\n\
        --r\r\nContent-Type: message/rfc822\r\n\r\n\
        From: someone@example.com\r\nSubject: invoice\r\n\r\nsecret body\r\n\
        --r--\r\n";
    let report = parse_message(raw.as_bytes(), &Limits::DEFAULT, deadline()).unwrap();
    let Body::Ruf(ruf) = &report.body else { panic!("expected a failure report") };
    assert_eq!(ruf.domain, "example.com");
    assert_eq!(ruf.source_ip, "192.0.2.7");
    assert!(ruf.headers.contains("Subject: invoice"));
    assert!(!String::from_utf8_lossy(&report.original).contains("secret body"));
}

#[test]
fn tighter_limits_apply() {
    let xml = include_bytes!("fixtures/google-aggregate.xml");
    let limits = Limits { max_records: 0, ..Limits::DEFAULT };
    assert!(dmarc::parse(xml, &limits, deadline()).is_err());
    let raw = format!("From: a@example.com\r\nContent-Type: text/xml\r\n\r\n{}", String::from_utf8_lossy(xml));
    match parse_message(raw.as_bytes(), &limits, deadline()) {
        Err(Error::Invalid(Kind::Dmarc, reason)) => {
            assert!(reason.as_str().contains("more than 0 records"), "{reason}")
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn base64_lines(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out.as_bytes().chunks(76).map(|l| std::str::from_utf8(l).unwrap()).collect::<Vec<_>>().join("\r\n")
}
