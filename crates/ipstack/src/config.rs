// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Configuration types for the custom IP stack.
// ABOUTME: Defines TUN, personality, and port binding settings.

//! Configuration for the custom IP stack.

use serde::Deserialize;
use std::net::Ipv4Addr;
use std::path::PathBuf;

/// Top-level IP stack configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct IpStackConfig {
    /// Whether the custom IP stack is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// TUN device settings.
    #[serde(default)]
    pub tun: TunDeviceConfig,

    /// OS personality to emulate.
    #[serde(default)]
    pub personality: PersonalityConfig,

    /// TCP ports to open (accept connections).
    #[serde(default)]
    pub tcp_ports: Vec<u16>,

    /// UDP ports to open (accept datagrams).
    #[serde(default)]
    pub udp_ports: Vec<u16>,
}

/// TUN device configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TunDeviceConfig {
    /// Device name (e.g. "honeypot0"). Empty for kernel auto-assign.
    #[serde(default = "default_tun_name")]
    pub name: String,

    /// IPv4 address for the TUN interface.
    #[serde(default = "default_tun_address")]
    pub address: Ipv4Addr,

    /// Network mask.
    #[serde(default = "default_tun_netmask")]
    pub netmask: Ipv4Addr,

    /// MTU.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

/// OS personality configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PersonalityConfig {
    /// Path to the nmap-os-db fingerprint database file.
    #[serde(default = "default_nmap_db_path")]
    pub nmap_os_db: PathBuf,

    /// Name of the OS fingerprint to emulate (substring match against nmap-os-db).
    /// Examples: "Linux 3.2 - 4.9", "Windows 10", "FreeBSD 12.0"
    #[serde(default = "default_personality_name")]
    pub name: String,
}

impl Default for IpStackConfig {
    fn default() -> Self {
        IpStackConfig {
            enabled: false,
            tun: TunDeviceConfig::default(),
            personality: PersonalityConfig::default(),
            tcp_ports: Vec::new(),
            udp_ports: Vec::new(),
        }
    }
}

impl Default for TunDeviceConfig {
    fn default() -> Self {
        TunDeviceConfig {
            name: default_tun_name(),
            address: default_tun_address(),
            netmask: default_tun_netmask(),
            mtu: default_mtu(),
        }
    }
}

impl Default for PersonalityConfig {
    fn default() -> Self {
        PersonalityConfig {
            nmap_os_db: default_nmap_db_path(),
            name: default_personality_name(),
        }
    }
}

fn default_tun_name() -> String {
    "honeypot0".to_string()
}

fn default_tun_address() -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, 1)
}

fn default_tun_netmask() -> Ipv4Addr {
    Ipv4Addr::new(255, 255, 255, 0)
}

fn default_mtu() -> u16 {
    1500
}

fn default_nmap_db_path() -> PathBuf {
    PathBuf::from("/usr/share/nmap/nmap-os-db")
}

fn default_personality_name() -> String {
    "Linux 3.2 - 4.9".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_full_config() {
        let toml = r#"
enabled = true
tcp_ports = [22, 80, 443, 445, 3389]
udp_ports = [53, 161]

[tun]
name = "honey0"
address = "192.168.100.1"
netmask = "255.255.255.0"
mtu = 1400

[personality]
nmap_os_db = "/opt/nmap/nmap-os-db"
name = "Windows 10 (1903)"
"#;
        let config: IpStackConfig = toml::from_str(toml).expect("parse");
        assert!(config.enabled);
        assert_eq!(config.tun.name, "honey0");
        assert_eq!(config.tun.address, Ipv4Addr::new(192, 168, 100, 1));
        assert_eq!(config.tun.mtu, 1400);
        assert_eq!(config.personality.name, "Windows 10 (1903)");
        assert_eq!(config.tcp_ports, vec![22, 80, 443, 445, 3389]);
        assert_eq!(config.udp_ports, vec![53, 161]);
    }

    #[test]
    fn test_deserialize_defaults() {
        let toml = "enabled = false\n";
        let config: IpStackConfig = toml::from_str(toml).expect("parse");
        assert!(!config.enabled);
        assert_eq!(config.tun.name, "honeypot0");
        assert_eq!(config.tun.address, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(config.personality.name, "Linux 3.2 - 4.9");
        assert!(config.tcp_ports.is_empty());
    }
}
