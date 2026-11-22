#![no_main]
//! The aggregate report XML on its own, with no MIME around it.

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use mail_reports::{dmarc, Limits};

const LIMITS: Limits = Limits { max_records: 500, max_auth_results: 2_000, max_field_bytes: 4096, ..Limits::DEFAULT };

fuzz_target!(|data: &[u8]| {
    if let Ok(report) = dmarc::parse(data, &LIMITS, Instant::now() + Duration::from_secs(2)) {
        assert!(report.records.len() <= LIMITS.max_records);
        let auth: usize = report.records.iter().map(|r| r.dkim.len() + r.spf.len()).sum();
        assert!(auth <= LIMITS.max_auth_results);
        assert!(report.org_name.len() <= LIMITS.max_field_bytes);
        assert!(!report.domain.is_empty() && !report.report_id.is_empty());
    }
});
