#![no_main]
//! The TLS report JSON on its own.

use libfuzzer_sys::fuzz_target;
use mail_reports::{tlsrpt, Limits};

const LIMITS: Limits = Limits { max_records: 50, ..Limits::DEFAULT };

fuzz_target!(|data: &[u8]| {
    if let Ok(report) = tlsrpt::parse(data, &LIMITS) {
        let items: usize = report.policies.iter().map(|p| 1 + p.failures.len() + p.mx_host.len()).sum();
        assert!(items <= LIMITS.max_records);
        assert!(!report.domain.is_empty());
    }
});
