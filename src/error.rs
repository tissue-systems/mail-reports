use std::fmt;

use crate::Kind;

/// Why a report file couldn't be read. The text is short, names no internal
/// detail and is safe to send back to the reporter, in an SMTP reply for
/// instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidReport(String);

impl InvalidReport {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        InvalidReport(reason.into())
    }

    /// The reason, as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InvalidReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidReport {}

impl From<String> for InvalidReport {
    fn from(reason: String) -> Self {
        InvalidReport(reason)
    }
}

impl From<&str> for InvalidReport {
    fn from(reason: &str) -> Self {
        InvalidReport(reason.to_string())
    }
}

/// Why [`parse_message`](crate::parse_message) found no report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Nothing in the message looks like a report.
    NoReport,
    /// The MIME structure is past the caps, before any report part was
    /// looked at.
    Malformed(String),
    /// A report part was found and couldn't be read. The [`InvalidReport`]
    /// says why; it's also this error's [`source`](std::error::Error::source).
    Invalid(Kind, InvalidReport),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoReport => f.write_str("no DMARC or TLS report found in this message"),
            Error::Malformed(reason) => f.write_str(reason),
            Error::Invalid(kind, _) => write!(f, "couldn't read the {kind} report"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Invalid(_, reason) => Some(reason),
            _ => None,
        }
    }
}
