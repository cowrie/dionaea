// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: TOML configuration loading with validation and env var overrides.
// ABOUTME: Defines the complete config structure for the dionaea daemon.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Top-level config file structure.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Core daemon settings.
    pub dionaea: DionaeaConfig,
    /// Logging configuration.
    pub logging: LoggingConfig,
    /// Module enable/disable flags and settings.
    pub modules: ModulesConfig,
    /// Processor pipeline configuration.
    #[serde(default)]
    pub processors: Vec<ProcessorConfig>,
}

/// Core daemon settings (listen addresses, limits, security).
#[derive(Debug, Deserialize)]
pub struct DionaeaConfig {
    /// Unix user to run as after privilege drop.
    #[serde(default)]
    pub user: Option<String>,
    /// Unix group to run as after privilege drop.
    #[serde(default)]
    pub group: Option<String>,
    /// Network listening configuration.
    pub listen: ListenConfig,
    /// Resource limits and rate limiting.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Admin interface settings (metrics, health).
    #[serde(default)]
    pub admin: AdminConfig,
    /// Download capture settings.
    #[serde(default)]
    pub download: DownloadConfig,
}

/// Download capture configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DownloadConfig {
    /// Directory to store captured malware binaries.
    #[serde(default = "default_download_dir")]
    pub dir: PathBuf,
    /// Suffix for in-progress downloads.
    #[serde(default = "default_download_suffix")]
    pub suffix: String,
    /// HTTP download timeout in seconds.
    #[serde(default = "default_download_timeout")]
    pub timeout_secs: u64,
    /// Maximum download size in bytes (0 = unlimited).
    #[serde(default = "default_download_size_limit")]
    pub size_limit_bytes: u64,
}

/// How the daemon discovers addresses to listen on.
#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    /// "manual" (use addresses list) or "getifaddrs" (discover from interfaces).
    #[serde(default = "default_listen_mode")]
    pub mode: String,
    /// Explicit addresses to bind when mode is "manual".
    #[serde(default = "default_addresses")]
    pub addresses: Vec<IpAddr>,
    /// Interface names to bind when mode is "getifaddrs".
    #[serde(default)]
    pub interfaces: Vec<String>,
}

/// Resource limits checked at connection accept time.
#[derive(Debug, Deserialize)]
pub struct LimitsConfig {
    /// Reject connections above this percentage of `RLIMIT_NOFILE`.
    #[serde(default = "default_max_fds_pct")]
    pub max_fds_pct: u32,
    /// Hard cap on concurrent connections.
    #[serde(default = "default_max_connections_total")]
    pub max_connections_total: u32,
    /// Max connections from a single source IP.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
    /// Bounded mpsc channel depth per connection.
    #[serde(default = "default_send_channel_capacity")]
    pub send_channel_capacity: usize,
    /// Bytes per read call (safety cap).
    #[serde(default = "default_recv_buffer_size")]
    pub recv_buffer_size: usize,
}

/// Admin interface (metrics, health check) — separate from honeypot services.
#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    /// Address for admin endpoints. Must differ from honeypot listen addresses.
    #[serde(default = "default_admin_listen")]
    pub listen: IpAddr,
}

/// Logging configuration with multiple targets.
///
/// The global log level gate is auto-derived as the most permissive level
/// across all configured targets. Per-target filtering is done by `DomainFilter`.
#[derive(Debug, Default, Deserialize)]
pub struct LoggingConfig {
    /// Log output targets (file, stdout).
    #[serde(default)]
    pub targets: Vec<LogTarget>,
}

/// A single log output target.
#[derive(Debug, Deserialize)]
pub struct LogTarget {
    /// "file" or "stdout".
    #[serde(rename = "type")]
    pub target_type: String,
    /// File path (required for type "file").
    pub path: Option<PathBuf>,
    /// "json" or "text".
    #[serde(default = "default_log_format")]
    pub format: String,
    /// Comma-separated level filter (e.g. "info,warning,error").
    #[serde(default = "default_log_levels")]
    pub levels: String,
    /// Domain glob pattern (e.g. "*" for all).
    #[serde(default = "default_log_domains")]
    pub domains: String,
}

/// Module enable/disable and settings.
#[derive(Debug, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ModulesConfig {
    /// Python module settings.
    #[serde(default)]
    pub python: PythonModuleConfig,
    /// Enable HTTP download module.
    #[serde(default = "default_true")]
    pub download: bool,
    /// Enable HTTP upload module (virustotal, hpfeeds, `submit_http`).
    #[serde(default = "default_true")]
    pub upload: bool,
    /// Pcap capture settings. Present = enabled, absent = disabled.
    #[serde(default)]
    pub pcap: Option<PcapConfig>,
    /// Enable netfilter queue module.
    #[serde(default)]
    pub nfq: bool,
    /// Enable netlink interface monitoring.
    #[serde(default)]
    pub netlink: bool,
}

/// Pcap passive capture configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PcapConfig {
    /// Interfaces to capture on. Use "any" for all interfaces.
    #[serde(default = "default_pcap_interfaces")]
    pub interfaces: Vec<String>,
}

/// Python module configuration.
#[derive(Debug, Deserialize)]
pub struct PythonModuleConfig {
    /// Python packages to import.
    #[serde(default = "default_python_imports")]
    pub imports: Vec<String>,
    /// Glob patterns for service config files.
    #[serde(default)]
    pub service_configs: Vec<String>,
    /// Glob patterns for ihandler config files.
    #[serde(default)]
    pub ihandler_configs: Vec<String>,
    /// Directory containing Python packages (added to sys.path).
    #[serde(default)]
    pub python_path: Option<PathBuf>,
}

/// Configuration for a single processor in the pipeline.
#[derive(Debug, Deserialize)]
pub struct ProcessorConfig {
    /// Processor type: "filter", "streamdumper", "shellcode".
    pub name: String,
    /// Unique label for cross-referencing (used by `next` to build tree).
    pub label: String,
    /// Labels of child processors (run after this one).
    #[serde(default)]
    pub next: Vec<String>,
    /// Allow rules (filter processor only).
    #[serde(default)]
    pub allow: Vec<FilterRuleConfig>,
    /// Deny rules (filter processor only).
    #[serde(default)]
    pub deny: Vec<FilterRuleConfig>,
    /// Directory path pattern for streamdumper output.
    pub path: Option<String>,
}

/// A filter rule matching connection type and/or protocol.
#[derive(Debug, Deserialize)]
pub struct FilterRuleConfig {
    /// Connection types to match ("accept", "connect"). Empty = any.
    #[serde(default)]
    pub types: Vec<String>,
    /// Protocol names to match ("httpd", "smbd"). Empty = any.
    #[serde(default)]
    pub protocols: Vec<String>,
}

// --- Defaults ---

fn default_listen_mode() -> String {
    "manual".to_string()
}
fn default_addresses() -> Vec<IpAddr> {
    vec!["0.0.0.0".parse().expect("valid IP")]
}
fn default_max_fds_pct() -> u32 {
    70
}
fn default_max_connections_total() -> u32 {
    10_000
}
fn default_max_connections_per_ip() -> u32 {
    50
}
fn default_send_channel_capacity() -> usize {
    256
}
fn default_recv_buffer_size() -> usize {
    65536
}
fn default_admin_listen() -> IpAddr {
    "127.0.0.1".parse().expect("valid IP")
}
fn default_log_format() -> String {
    "json".to_string()
}
fn default_log_levels() -> String {
    "info,warning,error,critical".to_string()
}
fn default_log_domains() -> String {
    "*".to_string()
}
fn default_true() -> bool {
    true
}
fn default_download_dir() -> PathBuf {
    PathBuf::from("var/dionaea/downloads/")
}
fn default_download_suffix() -> String {
    ".tmp".to_string()
}
fn default_download_timeout() -> u64 {
    30
}
fn default_download_size_limit() -> u64 {
    10 * 1024 * 1024 // 10 MB
}
fn default_python_imports() -> Vec<String> {
    vec!["dionaea".to_string()]
}
fn default_pcap_interfaces() -> Vec<String> {
    vec!["any".to_string()]
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_fds_pct: default_max_fds_pct(),
            max_connections_total: default_max_connections_total(),
            max_connections_per_ip: default_max_connections_per_ip(),
            send_channel_capacity: default_send_channel_capacity(),
            recv_buffer_size: default_recv_buffer_size(),
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        AdminConfig {
            listen: default_admin_listen(),
        }
    }
}

impl Default for DownloadConfig {
    fn default() -> Self {
        DownloadConfig {
            dir: default_download_dir(),
            suffix: default_download_suffix(),
            timeout_secs: default_download_timeout(),
            size_limit_bytes: default_download_size_limit(),
        }
    }
}

impl Default for ModulesConfig {
    fn default() -> Self {
        ModulesConfig {
            python: PythonModuleConfig::default(),
            download: true,
            upload: true,
            pcap: None,
            nfq: false,
            netlink: false,
        }
    }
}

impl Default for PythonModuleConfig {
    fn default() -> Self {
        PythonModuleConfig {
            imports: default_python_imports(),
            service_configs: Vec::new(),
            ihandler_configs: Vec::new(),
            python_path: None,
        }
    }
}

/// Load config from a TOML file, applying env var overrides.
pub fn load(path: &Path) -> Result<Config> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("failed to read {}: {e}", path.display())))?;
    let mut config: Config = toml::from_str(&content)?;
    apply_env_overrides(&mut config);
    validate(&config)?;
    Ok(config)
}

/// Load config from a TOML string (for testing).
pub fn load_from_str(content: &str) -> Result<Config> {
    let mut config: Config = toml::from_str(content)?;
    apply_env_overrides(&mut config);
    validate(&config)?;
    Ok(config)
}

/// Parse an integer env var into `target`, warning if the value is malformed.
fn parse_env_int<T: std::str::FromStr + std::fmt::Display>(name: &str, target: &mut T) {
    if let Ok(val) = std::env::var(name) {
        if let Ok(n) = val.parse() {
            *target = n;
        } else {
            tracing::warn!(var = name, value = %val, "ignoring non-numeric env override");
        }
    }
}

/// Apply environment variable overrides.
/// Format: DIONAEA_<SECTION>__<KEY> (double underscore for section separator).
fn apply_env_overrides(config: &mut Config) {
    if let Ok(val) = std::env::var("DIONAEA_DIONAEA__LISTEN__MODE") {
        config.dionaea.listen.mode = val;
    }
    if let Ok(val) = std::env::var("DIONAEA_DIONAEA__USER") {
        config.dionaea.user = Some(val);
    }
    if let Ok(val) = std::env::var("DIONAEA_DIONAEA__GROUP") {
        config.dionaea.group = Some(val);
    }
    parse_env_int(
        "DIONAEA_DIONAEA__LIMITS__MAX_FDS_PCT",
        &mut config.dionaea.limits.max_fds_pct,
    );
    parse_env_int(
        "DIONAEA_DIONAEA__LIMITS__MAX_CONNECTIONS_TOTAL",
        &mut config.dionaea.limits.max_connections_total,
    );
    parse_env_int(
        "DIONAEA_DIONAEA__LIMITS__MAX_CONNECTIONS_PER_IP",
        &mut config.dionaea.limits.max_connections_per_ip,
    );
}

/// Validate config consistency.
fn validate(config: &Config) -> Result<()> {
    // Listen mode must be "manual" or "getifaddrs"
    if config.dionaea.listen.mode != "manual" && config.dionaea.listen.mode != "getifaddrs" {
        return Err(Error::Config(format!(
            "listen.mode must be 'manual' or 'getifaddrs', got '{}'",
            config.dionaea.listen.mode
        )));
    }

    // Manual mode requires at least one address
    if config.dionaea.listen.mode == "manual" && config.dionaea.listen.addresses.is_empty() {
        return Err(Error::Config(
            "listen.mode is 'manual' but no addresses configured".to_string(),
        ));
    }

    // Admin listen must not overlap with honeypot listen addresses
    for addr in &config.dionaea.listen.addresses {
        if *addr == config.dionaea.admin.listen {
            // Allow 0.0.0.0 on honeypot side (wildcard) with 127.0.0.1 admin
            // Only reject if admin is explicitly set to a honeypot address
            if !addr.is_unspecified() {
                return Err(Error::Config(format!(
                    "admin.listen ({}) must not be the same as a honeypot listen address",
                    config.dionaea.admin.listen
                )));
            }
        }
    }

    // FD percentage must be 1-100
    if config.dionaea.limits.max_fds_pct == 0 || config.dionaea.limits.max_fds_pct > 100 {
        return Err(Error::Config(format!(
            "limits.max_fds_pct must be 1-100, got {}",
            config.dionaea.limits.max_fds_pct
        )));
    }

    // Log targets of type "file" must have a path
    for target in &config.logging.targets {
        if target.target_type == "file" && target.path.is_none() {
            return Err(Error::Config(
                "log target of type 'file' requires a 'path'".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CONFIG: &str = r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[logging]
[modules]
"#;

    #[test]
    fn test_load_minimal_config() {
        let config = load_from_str(MINIMAL_CONFIG).expect("parse minimal config");
        assert_eq!(config.dionaea.listen.mode, "manual");
        assert_eq!(config.dionaea.limits.max_fds_pct, 70);
        assert_eq!(config.dionaea.limits.max_connections_total, 10_000);
        assert!(config.logging.targets.is_empty());
    }

    #[test]
    fn test_full_config() {
        let toml = r#"
[dionaea]
user = "honeypot"
group = "honeypot"

[dionaea.listen]
mode = "getifaddrs"
interfaces = ["eth0", "eth1"]

[dionaea.limits]
max_fds_pct = 80
max_connections_total = 5000
max_connections_per_ip = 100
send_channel_capacity = 512
recv_buffer_size = 32768

[dionaea.admin]
listen = "127.0.0.1"

[logging]

[[logging.targets]]
type = "file"
path = "/var/log/dionaea/dionaea.log"
format = "json"
levels = "all,-debug"
domains = "*"

[[logging.targets]]
type = "stdout"
format = "text"
levels = "info,warning,error"
domains = "*"

[modules]
download = true

[modules.python]
imports = ["dionaea"]
service_configs = ["/etc/dionaea/services-enabled/*.toml"]
ihandler_configs = ["/etc/dionaea/ihandlers-enabled/*.toml"]
"#;
        let config = load_from_str(toml).expect("parse full config");
        assert_eq!(config.dionaea.user.as_deref(), Some("honeypot"));
        assert_eq!(config.dionaea.listen.mode, "getifaddrs");
        assert_eq!(config.dionaea.listen.interfaces, vec!["eth0", "eth1"]);
        assert_eq!(config.dionaea.limits.max_fds_pct, 80);
        assert_eq!(config.dionaea.limits.max_connections_total, 5000);
        assert_eq!(config.logging.targets.len(), 2);
        assert_eq!(config.logging.targets[0].target_type, "file");
        assert_eq!(config.logging.targets[1].target_type, "stdout");
        assert!(config.modules.download);
        assert!(config.modules.pcap.is_none());
        assert_eq!(config.modules.python.imports, vec!["dionaea"]);
    }

    #[test]
    fn test_config_round_trip_defaults() {
        let config = load_from_str(MINIMAL_CONFIG).expect("parse");
        assert_eq!(config.dionaea.user, None);
        assert_eq!(config.dionaea.group, None);
        assert_eq!(
            config.dionaea.admin.listen,
            "127.0.0.1".parse::<IpAddr>().expect("valid IP")
        );
        assert_eq!(config.dionaea.limits.recv_buffer_size, 65536);
        assert_eq!(config.dionaea.limits.send_channel_capacity, 256);
    }

    #[test]
    fn test_invalid_listen_mode() {
        let toml = r#"
[dionaea]
[dionaea.listen]
mode = "invalid"
[logging]
[modules]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("listen.mode"));
    }

    #[test]
    fn test_manual_mode_requires_addresses() {
        let toml = r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = []
[logging]
[modules]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("no addresses"));
    }

    #[test]
    fn test_file_target_requires_path() {
        let toml = r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[logging]
[[logging.targets]]
type = "file"
[modules]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("path"));
    }

    #[test]
    fn test_invalid_fds_pct() {
        let toml = r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[dionaea.limits]
max_fds_pct = 0
[logging]
[modules]
"#;
        let err = load_from_str(toml).unwrap_err();
        assert!(err.to_string().contains("max_fds_pct"));
    }

    #[test]
    fn test_download_config_defaults() {
        let config = load_from_str(MINIMAL_CONFIG).expect("parse");
        assert_eq!(
            config.dionaea.download.dir.to_str().unwrap(),
            "var/dionaea/downloads/"
        );
        assert_eq!(config.dionaea.download.suffix, ".tmp");
        assert_eq!(config.dionaea.download.timeout_secs, 30);
        assert_eq!(config.dionaea.download.size_limit_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn test_download_config_custom() {
        let toml = r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[dionaea.download]
dir = "/tmp/captures"
suffix = ".incomplete"
timeout_secs = 60
size_limit_bytes = 52428800
[logging]
[modules]
"#;
        let config = load_from_str(toml).expect("parse");
        assert_eq!(
            config.dionaea.download.dir.to_str().unwrap(),
            "/tmp/captures"
        );
        assert_eq!(config.dionaea.download.suffix, ".incomplete");
        assert_eq!(config.dionaea.download.timeout_secs, 60);
        assert_eq!(config.dionaea.download.size_limit_bytes, 52428800);
    }

    #[test]
    fn test_processor_config() {
        let toml = r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[logging]
[modules]

[[processors]]
name = "filter"
label = "filter_streamdumper"
next = ["streamdumper"]
allow = [
  { types = ["accept"] },
  { types = ["connect"], protocols = ["ftpctrl"] },
]
deny = [
  { protocols = ["ftpdata", "ftpdatacon"] },
]

[[processors]]
name = "streamdumper"
label = "streamdumper"
path = "var/lib/dionaea/bistreams/%Y-%m-%d/"

[[processors]]
name = "filter"
label = "filter_shellcode"
next = ["shellcode"]
allow = [
  { protocols = ["smbd", "epmapper", "mssqld", "httpd"] },
]

[[processors]]
name = "shellcode"
label = "shellcode"
"#;
        let config = load_from_str(toml).expect("parse processor config");
        assert_eq!(config.processors.len(), 4);

        let filter = &config.processors[0];
        assert_eq!(filter.name, "filter");
        assert_eq!(filter.label, "filter_streamdumper");
        assert_eq!(filter.next, vec!["streamdumper"]);
        assert_eq!(filter.allow.len(), 2);
        assert_eq!(filter.allow[0].types, vec!["accept"]);
        assert_eq!(filter.allow[1].protocols, vec!["ftpctrl"]);
        assert_eq!(filter.deny.len(), 1);
        assert_eq!(filter.deny[0].protocols, vec!["ftpdata", "ftpdatacon"]);

        let dumper = &config.processors[1];
        assert_eq!(dumper.name, "streamdumper");
        assert_eq!(
            dumper.path,
            Some("var/lib/dionaea/bistreams/%Y-%m-%d/".into())
        );

        let shellcode = &config.processors[3];
        assert_eq!(shellcode.name, "shellcode");
        assert!(shellcode.next.is_empty());
    }

    #[test]
    fn test_no_processors_by_default() {
        let config = load_from_str(MINIMAL_CONFIG).expect("parse");
        assert!(config.processors.is_empty());
    }

    #[test]
    fn test_pcap_config_none_by_default() {
        let config = load_from_str(MINIMAL_CONFIG).expect("parse");
        assert!(config.modules.pcap.is_none());
    }

    #[test]
    fn test_pcap_config_explicit_section() {
        let toml = r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[logging]
[modules]
[modules.pcap]
"#;
        let config = load_from_str(toml).expect("parse pcap config");
        let pcap = config.modules.pcap.as_ref().expect("pcap should be Some");
        assert_eq!(pcap.interfaces, vec!["any"]);
    }

    #[test]
    fn test_pcap_config_custom_interfaces() {
        let toml = r#"
[dionaea]
[dionaea.listen]
mode = "manual"
addresses = ["0.0.0.0"]
[logging]
[modules]
[modules.pcap]
interfaces = ["eth0", "eth1"]
"#;
        let config = load_from_str(toml).expect("parse pcap config");
        let pcap = config.modules.pcap.as_ref().expect("pcap should be Some");
        assert_eq!(pcap.interfaces, vec!["eth0", "eth1"]);
    }
}
