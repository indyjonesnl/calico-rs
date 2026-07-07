//! Typed Felix configuration with layered loading and restart-vs-live
//! classification.
//!
//! Upstream Felix (`felix/config`) merges configuration from defaults, the
//! config file, environment (`FELIX_*`), and the `FelixConfiguration` datastore
//! resource, and classifies each parameter as requiring a restart on change or
//! being live-updatable. This is a representative typed subset with the same
//! two behaviours that matter for correctness:
//!
//! 1. **Layered precedence**: defaults < datastore < environment (env wins).
//! 2. **Restart classification**: [`FelixConfig::requires_restart`] reports
//!    whether moving from one config to another needs an agent restart (a
//!    dataplane-mode/port change) vs. a live in-place update (log level, refresh
//!    intervals, failsafe ports).

#![allow(dead_code)] // wired into the daemon in a later task (T042)

use std::collections::BTreeMap;

/// Log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
}

/// How Calico rules attach to the host firewall backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IptablesBackend {
    Legacy,
    Nft,
    Auto,
}

/// nftables dataplane mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftablesMode {
    Enabled,
    Disabled,
    Auto,
}

/// What to do with traffic from workloads to the host by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointToHostAction {
    Drop,
    Return,
    Accept,
}

/// A configuration parse/validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "felix config error: {}", self.0)
    }
}
impl std::error::Error for ConfigError {}

/// Typed Felix configuration (representative subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FelixConfig {
    // --- Restart-required on change ---
    pub interface_prefix: String,
    pub iptables_backend: IptablesBackend,
    pub nftables_mode: NftablesMode,
    pub bpf_enabled: bool,
    pub prometheus_metrics_enabled: bool,
    pub prometheus_metrics_port: u16,
    pub health_port: u16,

    // --- Live-updatable ---
    pub felix_hostname: String,
    pub log_severity_screen: LogLevel,
    pub default_endpoint_to_host_action: EndpointToHostAction,
    pub iptables_refresh_interval_secs: u64,
    pub route_refresh_interval_secs: u64,
    pub failsafe_inbound_host_ports: Vec<u16>,
    pub failsafe_outbound_host_ports: Vec<u16>,
}

impl Default for FelixConfig {
    fn default() -> Self {
        Self {
            interface_prefix: "cali".to_string(),
            iptables_backend: IptablesBackend::Auto,
            nftables_mode: NftablesMode::Disabled,
            bpf_enabled: false,
            prometheus_metrics_enabled: false,
            prometheus_metrics_port: 9091,
            health_port: 9099,
            felix_hostname: String::new(),
            log_severity_screen: LogLevel::Info,
            default_endpoint_to_host_action: EndpointToHostAction::Drop,
            iptables_refresh_interval_secs: 90,
            route_refresh_interval_secs: 90,
            failsafe_inbound_host_ports: vec![22, 68, 179, 2379, 2380, 5473, 6443, 6666, 6667],
            failsafe_outbound_host_ports: vec![53, 67, 179, 2379, 2380, 5473, 6443, 6666, 6667],
        }
    }
}

impl FelixConfig {
    /// Load config by applying override layers in precedence order over the
    /// defaults. Pass layers low-to-high priority: e.g.
    /// `from_layers(&[&datastore, &env])` so environment wins.
    pub fn from_layers(layers: &[&BTreeMap<String, String>]) -> Result<Self, ConfigError> {
        let mut cfg = FelixConfig::default();
        for layer in layers {
            cfg.apply_overrides(layer)?;
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Apply a set of string key/value overrides (keys matched case-insensitively;
    /// unknown keys are ignored, as upstream tolerates unrecognized params).
    pub fn apply_overrides(&mut self, map: &BTreeMap<String, String>) -> Result<(), ConfigError> {
        for (k, v) in map {
            let key = k.trim().to_lowercase();
            let key = key.strip_prefix("felix_").unwrap_or(&key);
            match key {
                "interfaceprefix" => self.interface_prefix = v.clone(),
                "iptablesbackend" => self.iptables_backend = parse_iptables_backend(v)?,
                "nftablesmode" => self.nftables_mode = parse_nftables_mode(v)?,
                "bpfenabled" => self.bpf_enabled = parse_bool(v)?,
                "prometheusmetricsenabled" => self.prometheus_metrics_enabled = parse_bool(v)?,
                "prometheusmetricsport" => self.prometheus_metrics_port = parse_u16(v)?,
                "healthport" => self.health_port = parse_u16(v)?,
                "felixhostname" => self.felix_hostname = v.clone(),
                "logseverityscreen" => self.log_severity_screen = parse_log_level(v)?,
                "defaultendpointtohostaction" => {
                    self.default_endpoint_to_host_action = parse_e2h(v)?
                }
                "iptablesrefreshinterval" => self.iptables_refresh_interval_secs = parse_u64(v)?,
                "routerefreshinterval" => self.route_refresh_interval_secs = parse_u64(v)?,
                "failsafeinboundhostports" => {
                    self.failsafe_inbound_host_ports = parse_port_list(v)?
                }
                "failsafeoutboundhostports" => {
                    self.failsafe_outbound_host_ports = parse_port_list(v)?
                }
                _ => {} // unknown key: ignore
            }
        }
        Ok(())
    }

    /// Cross-field validation.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.interface_prefix.is_empty() {
            return Err(ConfigError("interfacePrefix must not be empty".into()));
        }
        if self.bpf_enabled && self.nftables_mode == NftablesMode::Enabled {
            return Err(ConfigError(
                "bpfEnabled and nftablesMode=Enabled are mutually exclusive dataplanes".into(),
            ));
        }
        Ok(())
    }

    /// Whether moving from `self` to `new` requires an agent restart (a change to
    /// a dataplane-selection or listening-port parameter) as opposed to a live
    /// in-place reconfiguration.
    pub fn requires_restart(&self, new: &FelixConfig) -> bool {
        self.interface_prefix != new.interface_prefix
            || self.iptables_backend != new.iptables_backend
            || self.nftables_mode != new.nftables_mode
            || self.bpf_enabled != new.bpf_enabled
            || self.prometheus_metrics_enabled != new.prometheus_metrics_enabled
            || self.prometheus_metrics_port != new.prometheus_metrics_port
            || self.health_port != new.health_port
    }
}

// ---- value parsers -------------------------------------------------------

fn parse_bool(v: &str) -> Result<bool, ConfigError> {
    match v.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        other => Err(ConfigError(format!("invalid bool: {other}"))),
    }
}

fn parse_u16(v: &str) -> Result<u16, ConfigError> {
    v.trim()
        .parse()
        .map_err(|_| ConfigError(format!("invalid u16: {v}")))
}

fn parse_u64(v: &str) -> Result<u64, ConfigError> {
    v.trim()
        .parse()
        .map_err(|_| ConfigError(format!("invalid u64: {v}")))
}

fn parse_log_level(v: &str) -> Result<LogLevel, ConfigError> {
    Ok(match v.trim().to_lowercase().as_str() {
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warning" | "warn" => LogLevel::Warning,
        "error" => LogLevel::Error,
        "fatal" => LogLevel::Fatal,
        other => return Err(ConfigError(format!("invalid log level: {other}"))),
    })
}

fn parse_iptables_backend(v: &str) -> Result<IptablesBackend, ConfigError> {
    Ok(match v.trim().to_lowercase().as_str() {
        "legacy" => IptablesBackend::Legacy,
        "nft" | "nftables" => IptablesBackend::Nft,
        "auto" => IptablesBackend::Auto,
        other => return Err(ConfigError(format!("invalid iptablesBackend: {other}"))),
    })
}

fn parse_nftables_mode(v: &str) -> Result<NftablesMode, ConfigError> {
    Ok(match v.trim().to_lowercase().as_str() {
        "enabled" => NftablesMode::Enabled,
        "disabled" => NftablesMode::Disabled,
        "auto" => NftablesMode::Auto,
        other => return Err(ConfigError(format!("invalid nftablesMode: {other}"))),
    })
}

fn parse_e2h(v: &str) -> Result<EndpointToHostAction, ConfigError> {
    Ok(match v.trim().to_uppercase().as_str() {
        "DROP" => EndpointToHostAction::Drop,
        "RETURN" => EndpointToHostAction::Return,
        "ACCEPT" => EndpointToHostAction::Accept,
        other => {
            return Err(ConfigError(format!(
                "invalid defaultEndpointToHostAction: {other}"
            )))
        }
    })
}

fn parse_port_list(v: &str) -> Result<Vec<u16>, ConfigError> {
    if v.trim().is_empty() {
        return Ok(Vec::new());
    }
    v.split(',').map(parse_u16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn defaults_are_sane() {
        let c = FelixConfig::default();
        assert_eq!(c.interface_prefix, "cali");
        assert_eq!(c.nftables_mode, NftablesMode::Disabled);
        assert!(!c.bpf_enabled);
        assert!(c.failsafe_inbound_host_ports.contains(&179)); // BGP
        c.validate().unwrap();
    }

    #[test]
    fn env_layer_overrides_datastore_layer() {
        let datastore = map(&[("LogSeverityScreen", "Warning"), ("BPFEnabled", "false")]);
        let env = map(&[("FELIX_BPFENABLED", "true")]); // env wins, FELIX_ prefix stripped
        let c = FelixConfig::from_layers(&[&datastore, &env]).unwrap();
        assert!(c.bpf_enabled); // from env
        assert_eq!(c.log_severity_screen, LogLevel::Warning); // from datastore
    }

    #[test]
    fn parses_enums_bool_and_port_list() {
        let c = FelixConfig::from_layers(&[&map(&[
            ("IptablesBackend", "nft"),
            ("NFTablesMode", "Enabled"),
            ("DefaultEndpointToHostAction", "Return"),
            ("PrometheusMetricsEnabled", "yes"),
            ("FailsafeInboundHostPorts", "22,179,6443"),
        ])])
        .unwrap();
        assert_eq!(c.iptables_backend, IptablesBackend::Nft);
        assert_eq!(c.nftables_mode, NftablesMode::Enabled);
        assert_eq!(
            c.default_endpoint_to_host_action,
            EndpointToHostAction::Return
        );
        assert!(c.prometheus_metrics_enabled);
        assert_eq!(c.failsafe_inbound_host_ports, vec![22, 179, 6443]);
    }

    #[test]
    fn unknown_keys_ignored() {
        let c = FelixConfig::from_layers(&[&map(&[("SomeFutureParam", "x")])]).unwrap();
        assert_eq!(c, FelixConfig::default());
    }

    #[test]
    fn invalid_values_error() {
        assert!(FelixConfig::from_layers(&[&map(&[("BPFEnabled", "maybe")])]).is_err());
        assert!(FelixConfig::from_layers(&[&map(&[("HealthPort", "not-a-port")])]).is_err());
        assert!(FelixConfig::from_layers(&[&map(&[("LogSeverityScreen", "loud")])]).is_err());
    }

    #[test]
    fn conflicting_dataplanes_rejected() {
        let err = FelixConfig::from_layers(&[&map(&[
            ("BPFEnabled", "true"),
            ("NFTablesMode", "Enabled"),
        ])])
        .unwrap_err();
        assert!(err.0.contains("mutually exclusive"));
    }

    #[test]
    fn restart_required_only_for_restart_fields() {
        let base = FelixConfig::default();

        // Live change: log level only.
        let mut live = base.clone();
        live.log_severity_screen = LogLevel::Debug;
        live.iptables_refresh_interval_secs = 30;
        assert!(!base.requires_restart(&live));

        // Restart change: switching on the eBPF dataplane.
        let mut restart = base.clone();
        restart.bpf_enabled = true;
        assert!(base.requires_restart(&restart));

        // Restart change: metrics port.
        let mut port = base.clone();
        port.prometheus_metrics_port = 9200;
        assert!(base.requires_restart(&port));
    }
}
