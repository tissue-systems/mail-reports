//! Rules that hold for every input, checked with quickcheck. The caps are
//! exact: a report parses under a cap equal to what it holds and is refused
//! under a cap one lower.

use std::io::Write;
use std::time::{Duration, Instant};

use mail_reports::unpack::{self, UnpackError};
use mail_reports::{dmarc, tlsrpt, Limits};
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
