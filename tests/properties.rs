//! Rules that hold for every input, checked with quickcheck. The caps are
//! exact: a report parses under a cap equal to what it holds and is refused
//! under a cap one lower. The rest feed each entry point input meant to
//! break it: nothing panics, an error is one clean line, and a report that
//! comes back is inside the caps.

use std::io::Write;
use std::time::{Duration, Instant};

use mail_reports::unpack::{self, UnpackError};
use mail_reports::{classify_part, dmarc, parse_message, ruf, tlsrpt, Body, Error, InvalidReport, Kind, Limits};
use quickcheck::{quickcheck, TestResult};

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

fn zip(data: &[u8]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file("report.xml", zip::write::SimpleFileOptions::default()).unwrap();
    zip.write_all(data).unwrap();
    zip.finish().unwrap().into_inner()
}

/// What `data` went in as comes back when it fits the cap, and nothing
/// comes back when it doesn't.
fn fits_or_too_large(result: Result<Vec<u8>, UnpackError>, data: &[u8], cap: u64) -> bool {
    match result {
        Ok(out) => data.len() as u64 <= cap && out == data,
        Err(UnpackError::TooLarge) => data.len() as u64 > cap,
        Err(_) => false,
    }
}

quickcheck! {
    fn gunzip_round_trips_up_to_the_cap(data: Vec<u8>, cap: u8) -> bool {
        fits_or_too_large(unpack::gunzip(&gzip(&data), cap.into()), &data, cap.into())
    }

    fn unzip_round_trips_up_to_the_cap(data: Vec<u8>, cap: u8) -> bool {
        fits_or_too_large(unpack::unzip(&zip(&data), cap.into()), &data, cap.into())
    }

    /// Each pair is one policy: how many `mx-host` names and how many
    /// failure details it holds.
    fn max_records_is_exact_for_a_tls_report(policies: Vec<(u8, u8)>) -> TestResult {
        if policies.is_empty() {
            return TestResult::discard();
        }
        let policies: Vec<(usize, usize)> = policies.iter().map(|&(h, f)| (h as usize % 8, f as usize % 8)).collect();
        let total: usize = policies.iter().map(|(hosts, failures)| 1 + hosts + failures).sum();
        let body: Vec<String> = policies
            .iter()
            .map(|&(hosts, failures)| {
                format!(
                    r#"{{"policy":{{"policy-type":"sts","policy-domain":"example.com","mx-host":[{}]}},"failure-details":[{}]}}"#,
                    vec![r#""mx.example.com""#; hosts].join(","),
                    vec!["{}"; failures].join(","),
                )
            })
            .collect();
        let json = format!(r#"{{"report-id":"1","policies":[{}]}}"#, body.join(","));
        let parses = |max_records| tlsrpt::parse(json.as_bytes(), &Limits { max_records, ..Limits::DEFAULT }).is_ok();
        TestResult::from_bool(parses(total) && !parses(total - 1))
    }

    /// Each pair is one record: how many DKIM results and how many SPF
    /// results it holds.
    fn max_auth_results_is_exact_for_an_aggregate_report(records: Vec<(u8, u8)>) -> TestResult {
        let records: Vec<(usize, usize)> = records.iter().map(|&(d, s)| (d as usize % 8, s as usize % 8)).collect();
        let total: usize = records.iter().map(|(dkim, spf)| dkim + spf).sum();
        if total == 0 {
            return TestResult::discard();
        }
        let body: String = records
            .iter()
            .map(|&(dkim, spf)| {
                format!("<record><auth_results>{}{}</auth_results></record>", "<dkim/>".repeat(dkim), "<spf/>".repeat(spf))
            })
            .collect();
        let xml = format!(
            "<feedback><report_metadata><report_id>1</report_id></report_metadata>\
             <policy_published><domain>example.com</domain></policy_published>{body}</feedback>"
        );
        let parses = |max_auth_results| {
            let limits = Limits { max_auth_results, ..Limits::DEFAULT };
            dmarc::parse(xml.as_bytes(), &limits, Instant::now() + Duration::from_secs(5)).is_ok()
        };
        TestResult::from_bool(parses(total) && !parses(total - 1))
    }
}

/// Caps small enough that a few random pieces reach them.
const SMALL: Limits = Limits { max_records: 3, max_auth_results: 8, max_field_bytes: 64, ..Limits::DEFAULT };

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn clean(reason: &InvalidReport) -> bool {
    reason.as_str().len() <= InvalidReport::MAX_LEN
        && reason.as_str().bytes().all(|b| b == b' ' || b.is_ascii_graphic())
}

fn within(body: &Body, limits: &Limits) -> bool {
    match body {
        Body::Dmarc(r) => {
            let auth: usize = r.records.iter().map(|rec| rec.dkim.len() + rec.spf.len()).sum();
            r.records.len() <= limits.max_records && auth <= limits.max_auth_results
        }
        Body::Tlsrpt(r) => {
            let items: usize = r.policies.iter().map(|p| 1 + p.failures.len() + p.mx_host.len()).sum();
            items <= limits.max_records
        }
        Body::Ruf(r) => r.headers.len() <= limits.max_ruf_header_bytes,
    }
}

/// Joins the pieces `seed` picks, with `sep` between them. Random bytes
/// almost never spell an element or a JSON key, so the inputs are built
/// from pieces that do. About one pick in sixteen is a broken piece, so most
/// inputs parse and the caps get tested too.
fn pieces(seed: &[u8], good: &[&str], broken: &[&str], sep: &str) -> String {
    let pick = |b: u8| if b >= 240 { broken[b as usize % broken.len()] } else { good[b as usize % good.len()] };
    seed.iter().map(|b| pick(*b)).collect::<Vec<_>>().join(sep)
}

const RECORDS: &[&str] = &[
    "<record/>",
    "<record><row><count>1</count></row></record>",
    "<record><auth_results><dkim/></auth_results></record>",
    "<record><auth_results><spf/><dkim><domain>a</domain></dkim></auth_results></record>",
    "<x:record xmlns:x=\"y\"><x:auth_results><x:spf/></x:auth_results></x:record>",
    "<auth_results><dkim/></auth_results>",
    "<x><y><z/></y></x>",
    "&amp;&#x41;<![CDATA[x]]>",
];

const BROKEN_RECORDS: &[&str] =
    &["<record><row><count>18446744073709551616</count></row></record>", "&lol;", "&#xD800;", "<", "</record>"];

const POLICIES: &[&str] = &[
    "{}",
    r#"{"policy":{"policy-domain":"example.com","mx-host":["a","b"]}}"#,
    r#"{"policy":{"mx-host":"a"},"failure-details":[{},{}]}"#,
    r#"{"policy":{"mx-host":null},"summary":{"total-failure-session-count":1}}"#,
    r#"{"x":[[{}]],"policies":[]}"#,
];

const BROKEN_POLICIES: &[&str] =
    &["1", r#"{"policy":{"mx-host":[1]}}"#, r#"{"failure-details":[{"failed-session-count":-1}]}"#, "{"];

quickcheck! {
    fn unpack_never_returns_more_than_the_cap(data: Vec<u8>, cap: u64) -> bool {
        [data.clone(), gzip(&data), zip(&data)]
            .iter()
            .all(|packed| unpack::unpack(packed, cap).map_or(true, |out| out.len() as u64 <= cap))
    }

    fn dmarc_stays_inside_the_caps(seed: Vec<u8>) -> bool {
        let xml = format!(
            "<feedback><report_metadata><report_id>1</report_id></report_metadata>\
             <policy_published><domain>example.com</domain></policy_published>{}</feedback>",
            pieces(&seed, RECORDS, BROKEN_RECORDS, "")
        );
        match dmarc::parse(xml.as_bytes(), &SMALL, deadline()) {
            Ok(r) => within(&Body::Dmarc(r), &SMALL),
            Err(e) => clean(&e),
        }
    }

    fn dmarc_takes_any_bytes(data: Vec<u8>) -> bool {
        dmarc::parse(&data, &SMALL, deadline()).err().is_none_or(|e| clean(&e))
    }

    fn tlsrpt_stays_inside_the_caps(seed: Vec<u8>) -> bool {
        let json = format!(r#"{{"report-id":"1","policies":[{}]}}"#, pieces(&seed, POLICIES, BROKEN_POLICIES, ","));
        match tlsrpt::parse(json.as_bytes(), &SMALL) {
            Ok(r) => within(&Body::Tlsrpt(r), &SMALL),
            Err(e) => clean(&e),
        }
    }

    fn tlsrpt_takes_any_bytes(data: Vec<u8>) -> bool {
        tlsrpt::parse(&data, &SMALL).err().is_none_or(|e| clean(&e))
    }

    fn a_message_stays_inside_the_caps(data: Vec<u8>, attached: Vec<u8>, ctype: u8) -> bool {
        let ctype = ["text/xml", "application/tlsrpt+json", "application/gzip", "application/zip"][ctype as usize % 4];
        let raw = [
            format!("From: a@example.com\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: {ctype}\r\n\r\n").as_bytes(),
            &attached,
            b"\r\n--b--\r\n",
        ]
        .concat();
        [raw, data].iter().all(|raw| match parse_message(raw, &SMALL, deadline()) {
            Ok(report) => {
                within(&report.body, &SMALL)
                    && report.header_from.len() <= SMALL.max_field_bytes
                    && !report.body.domain().is_empty()
            }
            Err(Error::Invalid(_, e)) => clean(&e),
            Err(_) => true,
        })
    }

    fn truncated_headers_fit_the_cap(data: Vec<u8>, max: u16) -> bool {
        ruf::truncate_headers(&data, max.into()).len() <= max.into()
    }

    fn classify_part_takes_any_text(ctype: String, filename: String) -> bool {
        classify_part(&ctype, &filename).is_none_or(|kind| kind != Kind::Ruf)
    }
}
