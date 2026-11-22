#![no_main]
//! gzip and zip. Whatever comes out is never larger than the cap.

use libfuzzer_sys::fuzz_target;
use mail_reports::unpack;

const CAP: u64 = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    for out in [unpack::unpack(data, CAP), unpack::gunzip(data, CAP), unpack::unzip(data, CAP)].into_iter().flatten() {
        assert!(out.len() as u64 <= CAP);
    }
});
