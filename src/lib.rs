#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::time::Instant;

use serde::Serialize;

pub mod dmarc;
mod error;
mod limits;
mod message;
pub mod ruf;
pub mod tlsrpt;
pub mod unpack;

pub use error::{Error, InvalidReport};
pub use limits::Limits;
pub use message::classify_part;

/// The three kinds of report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A DMARC aggregate report (`rua`).
    Dmarc,
    /// An SMTP TLS report (`TLSRPT`).
    Tlsrpt,
    /// A DMARC failure report (`ruf`).
    Ruf,
}

impl Kind {
    /// `"dmarc"`, `"tlsrpt"` or `"ruf"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Dmarc => "dmarc",
            Kind::Tlsrpt => "tlsrpt",
            Kind::Ruf => "ruf",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The parsed report. Serialises as the inner report alone, with no tag.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Body {
    /// A DMARC aggregate report.
    Dmarc(dmarc::Aggregate),
    /// An SMTP TLS report.
    Tlsrpt(tlsrpt::TlsReport),
    /// A DMARC failure report.
    Ruf(ruf::FailureReport),
}

impl Body {
    /// Which kind of report this is.
    pub fn kind(&self) -> Kind {
        match self {
            Body::Dmarc(_) => Kind::Dmarc,
            Body::Tlsrpt(_) => Kind::Tlsrpt,
            Body::Ruf(_) => Kind::Ruf,
        }
    }

    /// The domain the report is about: the aggregate report's
    /// `policy_published` domain, the TLS report's first policy domain, or
    /// the failure report's reported domain.
    pub fn domain(&self) -> &str {
        match self {
            Body::Dmarc(r) => &r.domain,
            Body::Tlsrpt(r) => &r.domain,
            Body::Ruf(r) => &r.domain,
        }
    }
}

/// A report found in a message.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    /// The parsed report.
    pub body: Body,
    /// The report file as it arrived, unpacked: the XML or the JSON. For a
    /// failure report, the `message/feedback-report` part, a blank line, and
    /// the reported message's header block after the cut.
    pub original: Vec<u8>,
    /// The address in the report message's own From field, lowercased, or
    /// empty.
    pub header_from: String,
}

impl Report {
    /// Which kind of report this is.
    pub fn kind(&self) -> Kind {
        self.body.kind()
    }
}

/// Finds and parses the report in a raw RFC 5322 message.
///
/// A failure report is recognised by the root part being a `multipart/report`
/// with `report-type=feedback-report`. Otherwise the first leaf part, in
/// document order and within [`Limits::max_mime_depth`], that classifies as
/// an aggregate or TLS report is unpacked and parsed; see [`classify_part`].
/// Attached messages are never opened.
///
/// Everything here is synchronous and CPU-bound. `deadline` is checked
/// between steps and inside the XML reader, so a parse stops soon after it
/// passes, though not to the microsecond.
pub fn parse_message(raw: &[u8], limits: &Limits, deadline: Instant) -> Result<Report, Error> {
    message::parse_message(raw, limits, deadline)
}
