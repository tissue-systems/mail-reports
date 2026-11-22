//! SMTP TLS reports (RFC 8460 §4), JSON, read with serde.
//!
//! A report holds three kinds of list: policies, a policy's failure details
//! and its `mx-host` names. All three are read against one budget of
//! [`Limits::max_records`], carried down through the parse as a
//! [`DeserializeSeed`], so a report over it fails at the element that
//! crosses the line and the rest of the list is never read. Fields the
//! parser doesn't know are skipped without being stored.

use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::{InvalidReport, Limits};

/// List elements the parse may still keep.
struct Budget {
    left: Cell<usize>,
    /// Set once an element was refused, so `parse` can tell that error from
    /// a JSON error.
    exhausted: Cell<bool>,
}

impl Budget {
    fn new(records: usize) -> Self {
        Budget { left: Cell::new(records), exhausted: Cell::new(false) }
    }

    fn take<E: de::Error>(&self) -> Result<(), E> {
        match self.left.get().checked_sub(1) {
            Some(left) => {
                self.left.set(left);
                Ok(())
            }
            None => {
                self.exhausted.set(true);
                Err(E::custom("too many records"))
            }
        }
    }
}

/// A JSON array into a `Vec`, each element counted before it's kept.
/// `element` reads one element: another seed, or `PhantomData<T>` for a type
/// that derives `Deserialize`.
struct List<'a, S> {
    budget: &'a Budget,
    element: S,
}

impl<'de, S: DeserializeSeed<'de> + Copy> DeserializeSeed<'de> for List<'_, S> {
    type Value = Vec<S::Value>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de, S: DeserializeSeed<'de> + Copy> Visitor<'de> for List<'_, S> {
    type Value = Vec<S::Value>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(item) = seq.next_element_seed(self.element)? {
            self.budget.take()?;
            out.push(item);
        }
        Ok(out)
    }
}

// The report as RFC 8460 writes it. Every field defaults, so a reporter
// that leaves one out still parses, and `parse` decides what's required.
// The three structs that hold a list are read by hand, because a derived
// impl has nowhere to carry the budget.

#[derive(Debug, Default)]
struct Raw {
    organization_name: String,
    date_range: RawDateRange,
    report_id: String,
    policies: Vec<RawPolicy>,
}

#[derive(Clone, Copy)]
struct RawSeed<'a>(&'a Budget);

impl<'de> DeserializeSeed<'de> for RawSeed<'_> {
    type Value = Raw;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Raw, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for RawSeed<'_> {
    type Value = Raw;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a TLS report object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Raw, A::Error> {
        let mut raw = Raw::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "organization-name" => raw.organization_name = map.next_value()?,
                "date-range" => raw.date_range = map.next_value()?,
                "report-id" => raw.report_id = map.next_value()?,
                "policies" => {
                    raw.policies = map.next_value_seed(List { budget: self.0, element: PolicySeed(self.0) })?
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(raw)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDateRange {
    #[serde(rename = "start-datetime")]
    start: String,
    #[serde(rename = "end-datetime")]
    end: String,
}

#[derive(Debug, Default)]
struct RawPolicy {
    policy: RawPolicyDesc,
    summary: RawSummary,
    failure_details: Vec<RawFailure>,
}

#[derive(Clone, Copy)]
struct PolicySeed<'a>(&'a Budget);

impl<'de> DeserializeSeed<'de> for PolicySeed<'_> {
    type Value = RawPolicy;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<RawPolicy, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for PolicySeed<'_> {
    type Value = RawPolicy;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a policy object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawPolicy, A::Error> {
        let mut policy = RawPolicy::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "policy" => policy.policy = map.next_value_seed(PolicyDescSeed(self.0))?,
                "summary" => policy.summary = map.next_value()?,
                "failure-details" => {
                    policy.failure_details =
                        map.next_value_seed(List { budget: self.0, element: PhantomData::<RawFailure> })?
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(policy)
    }
}

#[derive(Debug, Default)]
struct RawPolicyDesc {
    policy_type: String,
    policy_domain: String,
    mx_host: Vec<String>,
}

#[derive(Clone, Copy)]
struct PolicyDescSeed<'a>(&'a Budget);

impl<'de> DeserializeSeed<'de> for PolicyDescSeed<'_> {
    type Value = RawPolicyDesc;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<RawPolicyDesc, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for PolicyDescSeed<'_> {
    type Value = RawPolicyDesc;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a policy description object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawPolicyDesc, A::Error> {
        let mut desc = RawPolicyDesc::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "policy-type" => desc.policy_type = map.next_value()?,
                "policy-domain" => desc.policy_domain = map.next_value()?,
                "mx-host" => desc.mx_host = map.next_value_seed(MxHosts(self.0))?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(desc)
    }
}

/// `mx-host` is an array in RFC 8460, and some reporters send one string or
/// a null.
struct MxHosts<'a>(&'a Budget);

impl<'de> DeserializeSeed<'de> for MxHosts<'_> {
    type Value = Vec<String>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Vec<String>, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for MxHosts<'_> {
    type Value = Vec<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a host name or an array of host names")
    }

    fn visit_str<E: de::Error>(self, host: &str) -> Result<Vec<String>, E> {
        self.0.take()?;
        Ok(vec![host.to_owned()])
    }

    fn visit_unit<E: de::Error>(self) -> Result<Vec<String>, E> {
        Ok(Vec::new())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Vec<String>, A::Error> {
        List { budget: self.0, element: PhantomData::<String> }.visit_seq(seq)
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawSummary {
    #[serde(rename = "total-successful-session-count")]
    success: u64,
    #[serde(rename = "total-failure-session-count")]
    failure: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawFailure {
    #[serde(rename = "result-type")]
    result_type: String,
    #[serde(rename = "sending-mta-ip")]
    sending_ip: String,
    #[serde(rename = "receiving-mx-hostname")]
    receiving_mx: String,
    #[serde(rename = "failed-session-count")]
    count: u64,
}

/// One TLS report.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TlsReport {
    /// The first non-empty `policy-domain`, lowercased.
    pub domain: String,
    /// `organization-name`.
    pub org_name: String,
    /// `report-id`, unique per reporter.
    pub report_id: String,
    /// `start-datetime` as Unix seconds, or 0 when missing.
    pub date_begin: i64,
    /// `end-datetime` as Unix seconds, or 0 when missing.
    pub date_end: i64,
    /// Every policy, in order.
    pub policies: Vec<TlsPolicy>,
}

/// The sessions counted against one policy.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TlsPolicy {
    /// `sts`, `tlsa` or `no-policy-found`. Serialised as `type`.
    #[serde(rename = "type")]
    pub policy_type: String,
    /// `policy-domain`, lowercased.
    pub domain: String,
    /// Every `mx-host` the policy names, in order.
    pub mx_host: Vec<String>,
    /// `total-successful-session-count`.
    pub success: u64,
    /// `total-failure-session-count`.
    pub failure: u64,
    /// `failure-details`, in order.
    pub failures: Vec<TlsFailure>,
}

/// One kind of failure, from one sender to one MX.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TlsFailure {
    /// `result-type`, such as `certificate-expired`.
    pub result_type: String,
    /// `sending-mta-ip`.
    pub sending_ip: String,
    /// `receiving-mx-hostname`.
    pub receiving_mx: String,
    /// `failed-session-count`.
    pub count: u64,
}

/// Parses one TLS report file, already unpacked. The report's domain is the
/// first non-empty `policy-domain`, lowercased; dates become Unix seconds.
pub fn parse(json: &[u8], limits: &Limits) -> Result<TlsReport, InvalidReport> {
    let budget = Budget::new(limits.max_records);
    let mut de = serde_json::Deserializer::from_slice(json);
    let raw = RawSeed(&budget).deserialize(&mut de).and_then(|raw| de.end().map(|()| raw)).map_err(|e| {
        if budget.exhausted.get() {
            InvalidReport::new(format!("report has more than {} records", limits.max_records))
        } else {
            InvalidReport::new(format!("TLS report JSON: {e}"))
        }
    })?;
    let domain = raw
        .policies
        .iter()
        .map(|p| p.policy.policy_domain.trim().to_ascii_lowercase())
        .find(|d| !d.is_empty())
        .ok_or_else(|| InvalidReport::new("TLS report names no policy-domain"))?;
    if raw.report_id.trim().is_empty() {
        return Err("TLS report has no report-id".into());
    }
    Ok(TlsReport {
        domain,
        org_name: raw.organization_name,
        report_id: raw.report_id,
        date_begin: timestamp(&raw.date_range.start)?,
        date_end: timestamp(&raw.date_range.end)?,
        policies: raw
            .policies
            .into_iter()
            .map(|p| TlsPolicy {
                policy_type: p.policy.policy_type,
                domain: p.policy.policy_domain.to_ascii_lowercase(),
                mx_host: p.policy.mx_host,
                success: p.summary.success,
                failure: p.summary.failure,
                failures: p
                    .failure_details
                    .into_iter()
                    .map(|f| TlsFailure {
                        result_type: f.result_type,
                        sending_ip: f.sending_ip,
                        receiving_mx: f.receiving_mx,
                        count: f.count,
                    })
                    .collect(),
            })
            .collect(),
    })
}

/// RFC 3339 to Unix seconds; an empty date is 0.
fn timestamp(text: &str) -> Result<i64, InvalidReport> {
    if text.trim().is_empty() {
        return Ok(0);
    }
    chrono::DateTime::parse_from_rfc3339(text.trim())
        .map(|d| d.timestamp())
        .map_err(|_| format!("TLS report date is not RFC 3339: {text:.40}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_string_mx_host_is_accepted() {
        let r = parse(
            br#"{"report-id":"r1","policies":[{"policy":{"policy-type":"sts","policy-domain":"Example.com",
                 "mx-host":"mx.example.com"},"summary":{"total-successful-session-count":1,
                 "total-failure-session-count":0}}]}"#,
            &Limits::DEFAULT,
        )
        .unwrap();
        assert_eq!(r.domain, "example.com");
        assert_eq!(r.policies[0].mx_host, vec!["mx.example.com".to_string()]);
        assert_eq!((r.date_begin, r.date_end), (0, 0));
    }

    #[test]
    fn report_without_domain_fails() {
        assert!(parse(br#"{"report-id":"r1","policies":[]}"#, &Limits::DEFAULT).is_err());
        assert!(parse(b"not json", &Limits::DEFAULT).is_err());
    }
}
