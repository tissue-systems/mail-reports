use std::fmt;

use crate::Kind;

/// Why a report file couldn't be read. The text names no internal detail and
/// is safe to send back to the reporter, in an SMTP reply for instance: it
/// can quote a few bytes of the report, so it is held to one line of
/// printable ASCII, at most [`InvalidReport::MAX_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidReport(String);

impl InvalidReport {
    /// The longest reason, in bytes.
    pub const MAX_LEN: usize = 200;

    /// Every character that isn't printable ASCII becomes `?`, which takes
    /// line breaks and terminal escapes out of anything quoted from the
    /// report.
    pub(crate) fn new(reason: impl AsRef<str>) -> Self {
        let clean = reason
            .as_ref()
            .chars()
            .take(Self::MAX_LEN)
            .map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '?' })
            .collect();
        InvalidReport(clean)
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
        InvalidReport::new(reason)
    }
}

impl From<&str> for InvalidReport {
    fn from(reason: &str) -> Self {
        InvalidReport::new(reason)
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

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;

    quickcheck! {
        fn any_reason_comes_out_as_one_printable_line(reason: String) -> bool {
            let clean = InvalidReport::new(&reason);
            clean.as_str().len() <= InvalidReport::MAX_LEN
                && clean.as_str().bytes().all(|b| b == b' ' || b.is_ascii_graphic())
        }

        fn a_short_printable_reason_is_kept_as_written(seed: Vec<u8>) -> bool {
            let reason: String = seed.iter().take(InvalidReport::MAX_LEN).map(|b| (b' ' + b % 95) as char).collect();
            InvalidReport::new(&reason).as_str() == reason
        }
    }
}
