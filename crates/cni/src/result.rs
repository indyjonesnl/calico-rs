//! CNI result / error types (the JSON the plugin prints on stdout, per the CNI
//! spec). ADD prints a [`CniResult`]; failures print a [`CniError`]. Both are
//! pure and unit-tested; the plugin binary assembles and prints them.

use serde::Serialize;

/// A network interface in the CNI result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// The pod network namespace path (empty for host-side interfaces).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
}

/// An assigned address in the CNI result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IpConfig {
    /// CIDR, e.g. `10.99.0.7/32`.
    pub address: String,
    /// Index into the `interfaces` array this address belongs to.
    pub interface: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

/// A route in the CNI result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RouteEntry {
    pub dst: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw: Option<String>,
}

/// A successful CNI ADD result.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CniResult {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub interfaces: Vec<Interface>,
    pub ips: Vec<IpConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteEntry>,
}

impl CniResult {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("CNI result serializes")
    }
}

/// A CNI error result (also printed to stdout, with a non-zero exit).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CniError {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl CniError {
    /// A generic (code 7) error per the CNI spec's error-code guidance.
    pub fn new(cni_version: &str, msg: impl Into<String>) -> Self {
        Self {
            cni_version: cni_version.to_string(),
            code: 7,
            msg: msg.into(),
            details: None,
        }
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("CNI error serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_result_json_shape() {
        let r = CniResult {
            cni_version: "1.0.0".into(),
            interfaces: vec![
                Interface {
                    name: "cali123".into(),
                    mac: Some("ee:ee:ee:ee:ee:ee".into()),
                    sandbox: None,
                },
                Interface {
                    name: "eth0".into(),
                    mac: None,
                    sandbox: Some("/var/run/netns/cni-xyz".into()),
                },
            ],
            ips: vec![IpConfig {
                address: "10.99.0.7/32".into(),
                interface: 1,
                gateway: None,
            }],
            routes: vec![RouteEntry {
                dst: "0.0.0.0/0".into(),
                gw: None,
            }],
        };
        let json = r.to_json();
        assert!(json.contains("\"cniVersion\":\"1.0.0\""));
        assert!(json.contains("\"address\":\"10.99.0.7/32\""));
        assert!(json.contains("\"interface\":1"));
        assert!(json.contains("\"sandbox\":\"/var/run/netns/cni-xyz\""));
        assert!(json.contains("\"dst\":\"0.0.0.0/0\""));
        // Host interface omits its (absent) sandbox/mac cleanly.
        assert!(json.contains("\"name\":\"cali123\""));
    }

    #[test]
    fn error_json_shape() {
        let e = CniError::new("1.0.0", "datastore not ready");
        let json = e.to_json();
        assert!(json.contains("\"code\":7"));
        assert!(json.contains("\"msg\":\"datastore not ready\""));
        assert!(!json.contains("details"));
    }
}
