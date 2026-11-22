# Changelog

## 0.2.0 (2026-11-21)

Hardening against reports built to cost far more memory than their size. A
gzip of about 30 KB could make either parser allocate over a gigabyte.

- `Limits` has a new field, `max_auth_results` (default 40,000): the DKIM
  and SPF results an aggregate report may hold across all its records. A
  `Limits { .. }` written out in full needs the field added.
- TLS report lists are counted against `max_records` while the JSON is read,
  and `mx-host` names count too. The check used to run on the finished
  report.
- Aggregate report XML nested deeper than `dmarc::MAX_DEPTH` (32) is refused.
- A failure report whose `message/feedback-report` part is longer than
  `max_field_bytes` is refused.
- `InvalidReport` text is one line of printable ASCII, at most 200 bytes.
  It could carry a line break quoted from the report.
- A From address longer than `max_field_bytes` leaves `header_from` empty.
- `text/rfc822-headers` that opens on a blank line gives no headers; the
  first paragraph of what followed used to be kept as if it were headers.
- `unpack` with a cap of `u64::MAX` no longer overflows.
- Fuzz targets under `fuzz/`, and a fixed-seed mutation test and quickcheck
  property tests that run with the rest.

## 0.1.0 (2026-11-21)

First release. Pulled out of villus (then called afferent), the hook that
takes DMARC and TLS reports off Tissue Mast's inbound mail hosts.
