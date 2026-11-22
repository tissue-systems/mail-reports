#![no_main]
//! A whole raw message. A report that comes back has to be inside the caps
//! it was parsed under, and an error has to be one clean line.

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use mail_reports::{parse_message, Body, Error, InvalidReport, Limits};

const LIMITS: Limits =
    Limits { max_unpacked_bytes: 1024 * 1024, max_records: 500, max_auth_results: 2_000, ..Limits::DEFAULT };

fuzz_target!(|data: &[u8]| {
    match parse_message(data, &LIMITS, Instant::now() + Duration::from_secs(2)) {
        Ok(report) => {
            assert!(report.original.len() as u64 <= LIMITS.max_unpacked_bytes.max(data.len() as u64));
            assert!(report.header_from.len() <= LIMITS.max_field_bytes);
            assert!(!report.body.domain().is_empty());
            match &report.body {
                Body::Dmarc(r) => {
                    assert!(r.records.len() <= LIMITS.max_records);
                    let auth: usize = r.records.iter().map(|rec| rec.dkim.len() + rec.spf.len()).sum();
                    assert!(auth <= LIMITS.max_auth_results);
                }
                Body::Tlsrpt(r) => {
                    let items: usize = r.policies.iter().map(|p| 1 + p.failures.len() + p.mx_host.len()).sum();
                    assert!(items <= LIMITS.max_records);
                }
                Body::Ruf(r) => assert!(r.headers.len() <= LIMITS.max_ruf_header_bytes),
            }
        }
        Err(Error::Invalid(_, reason)) => {
            assert!(reason.as_str().len() <= InvalidReport::MAX_LEN);
            assert!(reason.as_str().bytes().all(|b| b == b' ' || b.is_ascii_graphic()));
        }
        Err(_) => {}
    }
});
