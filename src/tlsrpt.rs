//! SMTP TLS reports (RFC 8460 §4), JSON, read with serde.

use serde::{Deserialize, Serialize};

use crate::{InvalidReport, Limits};

// The report as RFC 8460 writes it. Every field defaults, so a reporter
// that leaves one out still parses, and `parse` decides what's required.

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
struct Raw {
    organization_name: String,
    date_range: RawDateRange,
    report_id: String,
    policies: Vec<RawPolicy>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawDateRange {
    #[serde(rename = "start-datetime")]
    start: String,
    #[serde(rename = "end-datetime")]
    end: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
struct RawPolicy {
    policy: RawPolicyDesc,
    summary: RawSummary,
    failure_details: Vec<RawFailure>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
struct RawPolicyDesc {
    policy_type: String,
    policy_domain: String,
    mx_host: OneOrMany,
}

/// `mx-host` is an array in RFC 8460, and some reporters send one string.
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl From<OneOrMany> for Vec<String> {
    fn from(hosts: OneOrMany) -> Self {
        match hosts {
            OneOrMany::None => Vec::new(),
            OneOrMany::One(host) => vec![host],
            OneOrMany::Many(hosts) => hosts,
        }
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
    let raw: Raw = serde_json::from_slice(json).map_err(|e| InvalidReport::new(format!("TLS report JSON: {e}")))?;
    let records: usize = raw.policies.len() + raw.policies.iter().map(|p| p.failure_details.len()).sum::<usize>();
    if records > limits.max_records {
        return Err(format!("report has more than {} records", limits.max_records).into());
    }
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
                mx_host: p.policy.mx_host.into(),
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
