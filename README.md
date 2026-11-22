# mail-reports

Reads the reports that mail systems send each other about your domain:
DMARC aggregate reports (`rua`, RFC 7489 appendix C and RFC 9990), DMARC
failure reports (`ruf`, RFC 6591 and RFC 9991) and SMTP TLS reports
(TLS-RPT, RFC 8460). Hand it the raw message as it arrived and it finds the
report part, unpacks it if it's gzipped or zipped, and parses it.

A report address is published in DNS, so anyone can send anything to it.
Every step has a cap: unpacked size, MIME depth and part count, records per
report, bytes per field, and a deadline for the whole parse. The defaults in
[`Limits`] fit real reporter output with a wide margin.

```rust
use std::time::{Duration, Instant};
use mail_reports::{parse_message, Body, Limits};

let raw = b"From: noreply-dmarc-support@google.com\r\n\
Subject: Report domain: example.com Submitter: google.com\r\n\
Content-Type: text/xml\r\n\
\r\n\
<feedback><report_metadata><org_name>google.com</org_name>\
<report_id>123</report_id></report_metadata>\
<policy_published><domain>example.com</domain><p>reject</p></policy_published>\
<record><row><source_ip>192.0.2.1</source_ip><count>2</count></row></record>\
</feedback>\r\n";

let report = parse_message(raw, &Limits::default(), Instant::now() + Duration::from_secs(5))?;
match &report.body {
    Body::Dmarc(agg) => {
        assert_eq!(agg.domain, "example.com");
        assert_eq!(agg.records[0].count, 2);
    }
    other => panic!("expected an aggregate report, got {:?}", other.kind()),
}
# Ok::<(), mail_reports::Error>(())
```

The parsed types implement `Serialize`, so a report goes to JSON as it is.
The parsers for each format are public too ([`dmarc::parse`],
[`tlsrpt::parse`]) for a file you already have out of its message, along
with [`unpack::unpack`] for the gzip and zip handling.

## What it doesn't do

It doesn't check DKIM, SPF or DMARC on the report message itself; a report
claiming to be from google.com is only as trustworthy as the signature you
check separately. It doesn't open attached messages looking for reports
inside them, or look past the first report part in a message. XML entities a
document declares are refused, never expanded.

## Licence

MIT or Apache-2.0, at your option.
