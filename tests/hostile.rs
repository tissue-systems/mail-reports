//! Input built to cost far more memory or time than its size, and input
//! that is simply garbage. Each of the first group is a few hundred
//! kilobytes that gzip to almost nothing.

use std::time::{Duration, Instant};

use mail_reports::{dmarc, parse_message, tlsrpt, unpack, Error, Kind, Limits};

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

const HEAD: &str = "<feedback><report_metadata><report_id>1</report_id></report_metadata>\
                    <policy_published><domain>example.com</domain></policy_published>";

#[test]
fn auth_results_are_capped_across_the_report() {
    let xml = format!("{HEAD}<record><auth_results>{}</auth_results></record></feedback>", "<dkim/>".repeat(100_000));
    let err = dmarc::parse(xml.as_bytes(), &Limits::DEFAULT, deadline()).unwrap_err();
    assert!(err.as_str().contains("DKIM and SPF results"), "{err}");

    let xml = format!("{HEAD}<record><auth_results>{}</auth_results></record></feedback>", "<spf/>".repeat(100_000));
    assert!(dmarc::parse(xml.as_bytes(), &Limits::DEFAULT, deadline()).is_err());

    // Spread over many records, the total still counts.
    let record = format!("<record><auth_results>{}</auth_results></record>", "<dkim/><spf/>".repeat(5));
    let xml = format!("{HEAD}{}</feedback>", record.repeat(5_000));
    assert!(dmarc::parse(xml.as_bytes(), &Limits::DEFAULT, deadline()).is_err());

    // A real report's shape, three results a record, is far inside it.
    let record = "<record><auth_results><dkim/><dkim/><spf/></auth_results></record>";
    let xml = format!("{HEAD}{}</feedback>", record.repeat(10_000));
    assert_eq!(dmarc::parse(xml.as_bytes(), &Limits::DEFAULT, deadline()).unwrap().records.len(), 10_000);
}

#[test]
fn deep_xml_is_refused() {
    let xml = format!("<feedback>{}", "<a>".repeat(100_000));
    let err = dmarc::parse(xml.as_bytes(), &Limits::DEFAULT, deadline()).unwrap_err();
    assert!(err.as_str().contains("nested"), "{err}");

    let xml = "<a>".repeat(100_000);
    assert!(dmarc::parse(xml.as_bytes(), &Limits::DEFAULT, deadline()).unwrap_err().as_str().contains("nested"));
}

#[test]
fn tls_lists_are_capped_while_they_are_read() {
    let wrap = |policies: &str| format!(r#"{{"report-id":"1","policies":[{policies}]}}"#);
    let domain = r#""policy-type":"sts","policy-domain":"example.com""#;

    let many_policies = wrap(&vec!["{}"; 100_000].join(","));
    let many_failures =
        wrap(&format!(r#"{{"policy":{{{domain}}},"failure-details":[{}]}}"#, vec!["{}"; 100_000].join(",")));
    let many_hosts = wrap(&format!(r#"{{"policy":{{{domain},"mx-host":[{}]}}}}"#, vec![r#""""#; 100_000].join(",")));
    for json in [many_policies, many_failures, many_hosts] {
        let err = tlsrpt::parse(json.as_bytes(), &Limits::DEFAULT).unwrap_err();
        assert!(err.as_str().contains("more than 10000 records"), "{err}");
    }

    // The cap is one budget for the whole report, not one per list.
    let policy = format!(r#"{{"policy":{{{domain},"mx-host":["a","b"]}},"failure-details":[{{}},{{}}]}}"#);
    let limits = Limits { max_records: 9, ..Limits::DEFAULT };
    assert!(tlsrpt::parse(wrap(&[policy.as_str(); 2].join(",")).as_bytes(), &limits).is_err());
    let limits = Limits { max_records: 10, ..Limits::DEFAULT };
    assert_eq!(tlsrpt::parse(wrap(&[policy.as_str(); 2].join(",")).as_bytes(), &limits).unwrap().policies.len(), 2);

    // A budget one parse used up is not carried into the next.
    let limits = Limits { max_records: 5, ..Limits::DEFAULT };
    for _ in 0..3 {
        assert!(tlsrpt::parse(wrap(&policy).as_bytes(), &limits).is_ok());
    }
}

#[test]
fn tls_mx_host_takes_a_string_a_list_or_null() {
    let report = |mx: &str| {
        let json = format!(
            r#"{{"report-id":"1","policies":[{{"policy":{{"policy-domain":"example.com","mx-host":{mx}}}}}]}}"#
        );
        tlsrpt::parse(json.as_bytes(), &Limits::DEFAULT).map(|r| r.policies[0].mx_host.clone())
    };
    assert_eq!(report(r#""mx.example.com""#).unwrap(), ["mx.example.com"]);
    assert_eq!(report(r#"["a.example.com","b.example.com"]"#).unwrap(), ["a.example.com", "b.example.com"]);
    assert!(report("null").unwrap().is_empty());
    assert!(report("7").is_err());
}

#[test]
fn error_text_is_one_printable_ascii_line() {
    let xml = format!("{HEAD}<record><row><count>1\r\n250 2.0.0 Ok\u{7f}\u{e9}</count></row></record></feedback>");
    let dmarc_err = dmarc::parse(xml.as_bytes(), &Limits::DEFAULT, deadline()).unwrap_err();

    let json = r#"{"report-id":"1","date-range":{"start-datetime":"x\r\n250 Ok"},
                   "policies":[{"policy":{"policy-domain":"example.com"}}]}"#;
    let tls_err = tlsrpt::parse(json.as_bytes(), &Limits::DEFAULT).unwrap_err();

    let entity = format!("<feedback><report_metadata><org_name>&{};</org_name>", "e".repeat(5_000));
    let entity_err = dmarc::parse(entity.as_bytes(), &Limits::DEFAULT, deadline()).unwrap_err();

    for err in [dmarc_err, tls_err, entity_err] {
        let text = err.as_str();
        assert!(text.bytes().all(|b| b == b' ' || b.is_ascii_graphic()), "{text:?}");
        assert!(text.len() <= 200, "{}", text.len());
    }
}

#[test]
fn a_huge_feedback_part_is_refused() {
    let raw = format!(
        "From: dmarc@reporter.example\r\n\
         Content-Type: multipart/report; report-type=feedback-report; boundary=\"r\"\r\n\
         \r\n\
         --r\r\nContent-Type: message/feedback-report\r\n\r\n\
         Reported-Domain: example.com\r\n{}\
         --r--\r\n",
        "a:\r\n".repeat(100_000)
    );
    match parse_message(raw.as_bytes(), &Limits::DEFAULT, deadline()) {
        Err(Error::Invalid(Kind::Ruf, reason)) => assert!(reason.as_str().contains("feedback"), "{reason}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_reported_message_with_no_headers_gives_none() {
    // text/rfc822-headers that opens on a blank line has no header block;
    // what follows is body and must not be kept.
    let raw = "From: dmarc@reporter.example\r\n\
        Content-Type: multipart/report; report-type=feedback-report; boundary=\"r\"\r\n\
        \r\n\
        --r\r\nContent-Type: message/feedback-report\r\n\r\n\
        Feedback-Type: auth-failure\r\nReported-Domain: example.com\r\n\
        --r\r\nContent-Type: text/rfc822-headers\r\n\r\n\
        \r\nsecret body\r\nmore of it\r\n\
        --r--\r\n";
    let report = parse_message(raw.as_bytes(), &Limits::DEFAULT, deadline()).unwrap();
    assert!(!String::from_utf8_lossy(&report.original).contains("secret body"));
}

#[test]
fn the_largest_cap_does_not_overflow() {
    assert_eq!(unpack::unpack(b"<feedback/>", u64::MAX).unwrap(), b"<feedback/>");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, b"<feedback/>").unwrap();
    assert_eq!(unpack::unpack(&gz.finish().unwrap(), u64::MAX).unwrap(), b"<feedback/>");
}

/// xorshift64: the same mutations on every run, with no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Flips, drops, repeats and splices bytes of real reports and feeds the
/// result to every entry point. Nothing may panic; errors are expected. The
/// fuzz targets under `fuzz/` look much harder, and this runs on every push.
#[test]
fn mutated_reports_never_panic() {
    let xml = include_bytes!("fixtures/google-aggregate.xml").to_vec();
    let json = include_bytes!("fixtures/microsoft-tlsrpt.json").to_vec();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &xml).unwrap();
    let gz = gz.finish().unwrap();
    let mail = [
        b"From: a@example.com\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\n\
          Content-Type: text/xml\r\n\r\n"
            .as_slice(),
        &xml,
        b"\r\n--b\r\nContent-Type: application/tlsrpt+json\r\n\r\n",
        &json,
        b"\r\n--b--\r\n",
    ]
    .concat();
    let ruf = b"From: dmarc@reporter.example\r\n\
        Content-Type: multipart/report; report-type=feedback-report; boundary=\"r\"\r\n\r\n\
        --r\r\nContent-Type: message/feedback-report\r\n\r\n\
        Feedback-Type: auth-failure\r\nReported-Domain: example.com\r\n\
        --r\r\nContent-Type: message/rfc822\r\n\r\nFrom: a@example.com\r\n\r\nbody\r\n--r--\r\n"
        .to_vec();
    let seeds = [xml, json, gz, mail, ruf];

    let limits = Limits { max_unpacked_bytes: 1024 * 1024, ..Limits::DEFAULT };
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..4_000 {
        let mut data = seeds[round % seeds.len()].clone();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(data.len());
            match rng.below(5) {
                0 => data[at] ^= 1 << rng.below(8),
                1 => data[at] = rng.next() as u8,
                2 => data.truncate(at),
                3 => {
                    let end = (at + rng.below(64)).min(data.len());
                    let piece = data[at..end].to_vec();
                    for _ in 0..rng.below(8) {
                        data.splice(at..at, piece.iter().copied());
                    }
                }
                _ => {
                    let other = &seeds[rng.below(seeds.len())];
                    let from = rng.below(other.len());
                    let piece = other[from..(from + rng.below(64)).min(other.len())].to_vec();
                    data.splice(at..at, piece);
                }
            }
            if data.is_empty() {
                break;
            }
        }
        let _ = parse_message(&data, &limits, deadline());
        let _ = dmarc::parse(&data, &limits, deadline());
        let _ = tlsrpt::parse(&data, &limits);
        let _ = unpack::unpack(&data, limits.max_unpacked_bytes);
    }
}
