// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Network address metadata for connections (IP, port, hostname).
// ABOUTME: Used by ConnectionMeta and exposed to Python via PyNodeInfo.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Network endpoint address info.
///
/// Stores the resolved address (IP + port) and optional hostname.
/// Each connection has a local and remote `NodeInfo`.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// IP address.
    pub host: IpAddr,
    /// Port number.
    pub port: u16,
    /// Hostname (from DNS reverse lookup or connect target).
    pub hostname: Option<String>,
}

impl NodeInfo {
    /// Create from a socket address.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        NodeInfo {
            host: addr.ip(),
            port: addr.port(),
            hostname: None,
        }
    }

    /// Create an empty/unset node info.
    pub fn unset() -> Self {
        NodeInfo {
            host: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port: 0,
            hostname: None,
        }
    }

    /// The socket address (IP:port).
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}

impl fmt::Display for NodeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref hostname) = self.hostname {
            write!(f, "{}:{} ({})", self.host, self.port, hostname)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_socket_addr() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().expect("valid");
        let info = NodeInfo::from_socket_addr(addr);
        assert_eq!(info.host, "192.168.1.1".parse::<IpAddr>().expect("valid"));
        assert_eq!(info.port, 8080);
        assert!(info.hostname.is_none());
    }

    #[test]
    fn test_display_without_hostname() {
        let info = NodeInfo::from_socket_addr("10.0.0.1:443".parse().expect("valid"));
        assert_eq!(info.to_string(), "10.0.0.1:443");
    }

    #[test]
    fn test_display_with_hostname() {
        let mut info = NodeInfo::from_socket_addr("10.0.0.1:443".parse().expect("valid"));
        info.hostname = Some("example.com".to_string());
        assert_eq!(info.to_string(), "10.0.0.1:443 (example.com)");
    }

    #[test]
    fn test_ipv6() {
        let addr: SocketAddr = "[::1]:22".parse().expect("valid");
        let info = NodeInfo::from_socket_addr(addr);
        assert_eq!(info.to_string(), "::1:22");
    }

    #[test]
    fn test_unset() {
        let info = NodeInfo::unset();
        assert_eq!(info.port, 0);
        assert!(info.host.is_unspecified());
    }
}
