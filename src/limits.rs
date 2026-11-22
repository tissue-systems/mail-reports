//! The caps, in one struct.

/// Every size, count and depth the parsers will accept. The defaults fit
/// real reporter output with a wide margin: an aggregate report from a large
/// mailbox provider is a few hundred records and well under a megabyte
/// unpacked.
///
/// The time budget is not here. Each parse takes a deadline, because the
/// caller usually wants one clock for the whole message, unpacking
/// included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest report file after gunzip or unzip.
    pub max_unpacked_bytes: u64,
    /// MIME nesting, the root message included. Parts deeper than this are
    /// never looked at.
    pub max_mime_depth: usize,
    /// MIME parts in one message. A report message has two or three.
    pub max_mime_parts: usize,
    /// Lines starting with `--` allowed before the message is parsed at all.
    /// Each multipart delimiter is one; a real report has three or four, and
    /// base64 never starts a line with `-`.
    pub max_boundary_lines: usize,
    /// Records in one report: aggregate `<record>`s, or TLS report policies
    /// plus their failure details plus their `mx-host` names. The TLS count
    /// is kept while the JSON is read, so a list past it is never built.
    pub max_records: usize,
    /// DKIM and SPF results in one aggregate report, counted across all its
    /// records. A record carries one SPF result and one DKIM result per
    /// signature, so four per record is already generous.
    pub max_auth_results: usize,
    /// Any one string field in a parsed report. Also the largest
    /// `message/feedback-report` part of a failure report, and the longest
    /// From address kept as [`Report::header_from`](crate::Report::header_from).
    pub max_field_bytes: usize,
    /// The reported message's header block in a failure report. Longer
    /// blocks are cut at a line break, not refused.
    pub max_ruf_header_bytes: usize,
}

impl Limits {
    /// The defaults, as a `const`.
    pub const DEFAULT: Limits = Limits {
        max_unpacked_bytes: 32 * 1024 * 1024,
        max_mime_depth: 4,
        max_mime_parts: 64,
        max_boundary_lines: 256,
        max_records: 10_000,
        max_auth_results: 40_000,
        max_field_bytes: 64 * 1024,
        max_ruf_header_bytes: 16 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Limits::DEFAULT
    }
}

/// `65536` as `64 KiB`, for error text.
pub(crate) fn size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB && bytes.is_multiple_of(KIB) {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} bytes")
    }
}
