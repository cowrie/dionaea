// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Per-IP connection counting, global FD/total checks, and IP deny list.
// ABOUTME: Pure logic — injectable FD count for testability. Deny list behind feature flag.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

/// Why a connection was rejected at accept time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// Too many connections from this source IP.
    PerIpLimit {
        /// Source IP that exceeded the limit.
        ip: IpAddr,
        /// Current connection count from this IP.
        current: u32,
        /// Configured per-IP limit.
        limit: u32,
    },
    /// Global connection count exceeded.
    TotalLimit {
        /// Current total connection count.
        current: u32,
        /// Configured total limit.
        limit: u32,
    },
    /// File descriptor usage too high.
    FdLimit {
        /// Current FD count.
        used: u64,
        /// OS soft limit for file descriptors.
        soft_limit: u64,
        /// Configured threshold percentage.
        threshold_pct: u32,
    },
    /// IP is on the deny list.
    Denied {
        /// Denied source IP.
        ip: IpAddr,
    },
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectReason::PerIpLimit { ip, current, limit } => {
                write!(f, "per-IP limit: {ip} has {current}/{limit} connections")
            }
            RejectReason::TotalLimit { current, limit } => {
                write!(f, "total limit: {current}/{limit} connections")
            }
            RejectReason::FdLimit {
                used,
                soft_limit,
                threshold_pct,
            } => {
                write!(
                    f,
                    "FD limit: {used}/{soft_limit} ({threshold_pct}% threshold)"
                )
            }
            RejectReason::Denied { ip } => {
                write!(f, "denied: {ip}")
            }
        }
    }
}

/// Tracks per-IP connection counts and enforces global limits.
pub struct ConnectionLimits {
    /// Per-IP active connection counts.
    per_ip: DashMap<IpAddr, AtomicU32>,
    /// Max connections from one IP.
    max_per_ip: u32,
    /// Max total connections.
    max_total: u32,
    /// Reject when FD usage exceeds this percentage of soft limit.
    max_fds_pct: u32,
    /// Deny list (CIDR matching, optional TTL).
    #[cfg(feature = "deny-list")]
    deny_list: std::sync::RwLock<IpDenyList>,
}

impl ConnectionLimits {
    /// Create with the given limits.
    pub fn new(max_per_ip: u32, max_total: u32, max_fds_pct: u32) -> Self {
        let max_fds_pct = max_fds_pct.min(100);
        ConnectionLimits {
            per_ip: DashMap::new(),
            max_per_ip,
            max_total,
            max_fds_pct,
            #[cfg(feature = "deny-list")]
            deny_list: std::sync::RwLock::new(IpDenyList::new()),
        }
    }

    /// Check whether a new connection from `ip` should be accepted.
    ///
    /// `current_total` is the current number of active connections (from the registry).
    /// `fd_count` is the number of open file descriptors (injectable for tests).
    /// `fd_soft_limit` is the `RLIMIT_NOFILE` soft limit.
    pub fn check(
        &self,
        ip: IpAddr,
        current_total: u32,
        fd_count: u64,
        fd_soft_limit: u64,
    ) -> Result<(), RejectReason> {
        // Check deny list first
        #[cfg(feature = "deny-list")]
        {
            let deny = self.deny_list.read().expect("deny list lock poisoned");
            if deny.contains(ip) {
                return Err(RejectReason::Denied { ip });
            }
        }

        // Check FD limit
        if fd_soft_limit > 0 {
            let threshold = fd_soft_limit / 100 * u64::from(self.max_fds_pct);
            if fd_count >= threshold {
                return Err(RejectReason::FdLimit {
                    used: fd_count,
                    soft_limit: fd_soft_limit,
                    threshold_pct: self.max_fds_pct,
                });
            }
        }

        // Check total limit
        if current_total >= self.max_total {
            return Err(RejectReason::TotalLimit {
                current: current_total,
                limit: self.max_total,
            });
        }

        // Check per-IP limit
        let current_ip = self.ip_count(ip);
        if current_ip >= self.max_per_ip {
            return Err(RejectReason::PerIpLimit {
                ip,
                current: current_ip,
                limit: self.max_per_ip,
            });
        }

        Ok(())
    }

    /// Increment the per-IP counter. Call after accepting a connection.
    pub fn increment(&self, ip: IpAddr) -> u32 {
        self.per_ip
            .entry(ip)
            .or_insert_with(|| AtomicU32::new(0))
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    /// Decrement the per-IP counter. Call when a connection closes.
    /// Removes the entry when count reaches 0.
    pub fn decrement(&self, ip: IpAddr) -> u32 {
        if let Some(entry) = self.per_ip.get(&ip) {
            let prev = entry.fetch_sub(1, Ordering::Relaxed);
            if prev <= 1 {
                // Clean up zero entries to prevent unbounded growth
                drop(entry);
                self.per_ip
                    .remove_if(&ip, |_, v| v.load(Ordering::Relaxed) == 0);
                return 0;
            }
            return prev - 1;
        }
        0
    }

    /// Current connection count for an IP.
    pub fn ip_count(&self, ip: IpAddr) -> u32 {
        self.per_ip
            .get(&ip)
            .map_or(0, |v| v.load(Ordering::Relaxed))
    }

    /// Number of tracked IPs.
    pub fn tracked_ips(&self) -> usize {
        self.per_ip.len()
    }

    /// Get a reference to the deny list.
    #[cfg(feature = "deny-list")]
    pub fn deny_list(&self) -> &std::sync::RwLock<IpDenyList> {
        &self.deny_list
    }
}

// --- IP Deny List ---

#[cfg(feature = "deny-list")]
mod deny_list {
    use ip_network_table::IpNetworkTable;
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    /// Entry in the deny list, with optional expiry.
    #[derive(Debug, Clone)]
    pub struct DenyEntry {
        /// When this entry was added.
        pub added: Instant,
        /// How long until this entry expires. None means permanent.
        pub ttl: Option<Duration>,
        /// Human-readable reason for the deny.
        pub reason: String,
    }

    impl DenyEntry {
        /// Whether this entry has expired.
        pub fn is_expired(&self) -> bool {
            match self.ttl {
                Some(ttl) => self.added.elapsed() >= ttl,
                None => false,
            }
        }
    }

    /// IP deny list with CIDR matching and optional TTL per entry.
    pub struct IpDenyList {
        /// CIDR prefix table for fast lookups.
        table: IpNetworkTable<DenyEntry>,
    }

    impl IpDenyList {
        /// Create an empty deny list.
        pub fn new() -> Self {
            IpDenyList {
                table: IpNetworkTable::new(),
            }
        }

        /// Add an IP or CIDR to the deny list.
        pub fn add(
            &mut self,
            network: ip_network::IpNetwork,
            ttl: Option<Duration>,
            reason: String,
        ) {
            self.table.insert(
                network,
                DenyEntry {
                    added: Instant::now(),
                    ttl,
                    reason,
                },
            );
        }

        /// Check if an IP is denied (not expired).
        pub fn contains(&self, ip: IpAddr) -> bool {
            self.table
                .longest_match(ip)
                .is_some_and(|(_, entry)| !entry.is_expired())
        }

        /// Remove an IP/CIDR from the deny list.
        pub fn remove(&mut self, network: ip_network::IpNetwork) -> bool {
            self.table.remove(network).is_some()
        }

        /// Remove all expired entries. Returns count removed.
        pub fn cleanup_expired(&mut self) -> usize {
            // Collect expired networks first to avoid borrow issues
            let expired: Vec<ip_network::IpNetwork> = self
                .table
                .iter()
                .filter(|(_, entry)| entry.is_expired())
                .map(|(net, _)| net)
                .collect();
            let count = expired.len();
            for net in expired {
                self.table.remove(net);
            }
            count
        }

        /// Number of entries (including potentially expired ones).
        pub fn len(&self) -> usize {
            self.table.iter().count()
        }

        /// Whether the deny list is empty.
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    impl Default for IpDenyList {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(feature = "deny-list")]
pub use deny_list::{DenyEntry, IpDenyList};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_ip_increment_decrement() {
        let limits = ConnectionLimits::new(50, 10_000, 70);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert_eq!(limits.ip_count(ip), 0);
        assert_eq!(limits.increment(ip), 1);
        assert_eq!(limits.increment(ip), 2);
        assert_eq!(limits.ip_count(ip), 2);

        assert_eq!(limits.decrement(ip), 1);
        assert_eq!(limits.ip_count(ip), 1);

        assert_eq!(limits.decrement(ip), 0);
        assert_eq!(limits.ip_count(ip), 0);
    }

    #[test]
    fn test_cleanup_at_zero() {
        let limits = ConnectionLimits::new(50, 10_000, 70);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        limits.increment(ip);
        assert_eq!(limits.tracked_ips(), 1);

        limits.decrement(ip);
        assert_eq!(limits.tracked_ips(), 0);
    }

    #[test]
    fn test_per_ip_limit_rejection() {
        let limits = ConnectionLimits::new(2, 10_000, 70);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        limits.increment(ip);
        limits.increment(ip);

        let result = limits.check(ip, 2, 10, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            RejectReason::PerIpLimit { current, limit, .. } => {
                assert_eq!(current, 2);
                assert_eq!(limit, 2);
            }
            other => panic!("expected PerIpLimit, got {other}"),
        }
    }

    #[test]
    fn test_total_limit_rejection() {
        let limits = ConnectionLimits::new(50, 100, 70);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = limits.check(ip, 100, 10, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            RejectReason::TotalLimit { current, limit } => {
                assert_eq!(current, 100);
                assert_eq!(limit, 100);
            }
            other => panic!("expected TotalLimit, got {other}"),
        }
    }

    #[test]
    fn test_fd_limit_rejection() {
        let limits = ConnectionLimits::new(50, 10_000, 70);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // 700/1000 = 70%, which is at the threshold
        let result = limits.check(ip, 0, 700, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            RejectReason::FdLimit {
                used,
                soft_limit,
                threshold_pct,
            } => {
                assert_eq!(used, 700);
                assert_eq!(soft_limit, 1000);
                assert_eq!(threshold_pct, 70);
            }
            other => panic!("expected FdLimit, got {other}"),
        }
    }

    #[test]
    fn test_fd_below_threshold_passes() {
        let limits = ConnectionLimits::new(50, 10_000, 70);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // 699/1000 = 69.9%, below 70%
        assert!(limits.check(ip, 0, 699, 1000).is_ok());
    }

    #[test]
    fn test_all_checks_pass() {
        let limits = ConnectionLimits::new(50, 10_000, 70);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert!(limits.check(ip, 5, 100, 1000).is_ok());
    }

    #[test]
    fn test_multiple_ips() {
        let limits = ConnectionLimits::new(2, 10_000, 70);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        limits.increment(ip1);
        limits.increment(ip1);
        limits.increment(ip2);

        assert_eq!(limits.ip_count(ip1), 2);
        assert_eq!(limits.ip_count(ip2), 1);
        assert_eq!(limits.tracked_ips(), 2);

        // ip1 at limit, ip2 not
        assert!(limits.check(ip1, 3, 10, 1000).is_err());
        assert!(limits.check(ip2, 3, 10, 1000).is_ok());
    }
}

#[cfg(all(test, feature = "deny-list"))]
mod deny_list_tests {
    use super::*;
    use ip_network::IpNetwork;
    use std::time::Duration;

    #[test]
    fn test_empty_deny_list_allows_all() {
        let deny = IpDenyList::new();
        assert!(deny.is_empty());
        assert!(!deny.contains("10.0.0.1".parse().unwrap()));
        assert!(!deny.contains("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_exact_ip_deny() {
        let mut deny = IpDenyList::new();
        let net: IpNetwork = "10.0.0.1/32".parse().unwrap();
        deny.add(net, None, "scanner".to_string());

        assert!(deny.contains("10.0.0.1".parse().unwrap()));
        assert!(!deny.contains("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_cidr_range_deny() {
        let mut deny = IpDenyList::new();
        let net: IpNetwork = "10.0.0.0/24".parse().unwrap();
        deny.add(net, None, "bad subnet".to_string());

        assert!(deny.contains("10.0.0.1".parse().unwrap()));
        assert!(deny.contains("10.0.0.254".parse().unwrap()));
        assert!(!deny.contains("10.0.1.1".parse().unwrap()));
    }

    #[test]
    fn test_remove_deny_entry() {
        let mut deny = IpDenyList::new();
        let net: IpNetwork = "10.0.0.1/32".parse().unwrap();
        deny.add(net, None, "temp".to_string());
        assert!(deny.contains("10.0.0.1".parse().unwrap()));

        assert!(deny.remove(net));
        assert!(!deny.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ttl_expiry() {
        let mut deny = IpDenyList::new();
        let net: IpNetwork = "10.0.0.1/32".parse().unwrap();
        // TTL of 0 = already expired
        deny.add(net, Some(Duration::from_secs(0)), "expired".to_string());

        // Should not match because it's expired
        assert!(!deny.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut deny = IpDenyList::new();
        let net1: IpNetwork = "10.0.0.1/32".parse().unwrap();
        let net2: IpNetwork = "10.0.0.2/32".parse().unwrap();

        deny.add(net1, Some(Duration::from_secs(0)), "expired".to_string());
        deny.add(net2, None, "permanent".to_string());

        assert_eq!(deny.len(), 2);
        let removed = deny.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(deny.len(), 1);
        assert!(deny.contains("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_deny_list_integration_with_limits() {
        let limits = ConnectionLimits::new(50, 10_000, 70);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Should pass without deny entry
        assert!(limits.check(ip, 0, 10, 1000).is_ok());

        // Add to deny list
        {
            let mut deny = limits.deny_list().write().unwrap();
            deny.add(
                "10.0.0.1/32".parse().unwrap(),
                None,
                "bad actor".to_string(),
            );
        }

        // Should now be rejected
        let result = limits.check(ip, 0, 10, 1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            RejectReason::Denied { ip: denied_ip } => {
                assert_eq!(denied_ip, ip);
            }
            other => panic!("expected Denied, got {other}"),
        }
    }
}
