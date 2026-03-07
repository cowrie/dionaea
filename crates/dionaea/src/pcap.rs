// SPDX-License-Identifier: GPL-3.0-only
// ABOUTME: Passive pcap capture for detecting TCP RST rejections.
// ABOUTME: Sniffs interfaces for RST packets from honeypot IPs and emits tcp.reject incidents.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::config::PcapConfig;

/// Snapshot length — only need headers, not payload.
const SNAPLEN: i32 = 80;

/// Read timeout in milliseconds (matches C module).
const TIMEOUT_MS: i32 = 50;

/// Link-layer type constants.
const DLT_EN10MB: i32 = 1;
const DLT_LINUX_SLL: i32 = 113;

/// Ethertype constants.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// IP protocol number for TCP.
const IPPROTO_TCP: u8 = 6;

/// Parsed information about a rejected TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectInfo {
    /// Source IP (the honeypot address that sent the RST).
    pub local_addr: IpAddr,
    /// Source port.
    pub local_port: u16,
    /// Destination IP (the remote attacker).
    pub remote_addr: IpAddr,
    /// Destination port.
    pub remote_port: u16,
}

/// Parse a captured packet from link-layer through TCP headers.
///
/// Returns `Some(RejectInfo)` if the packet is a TCP RST with seq=0,
/// `None` otherwise.
pub fn parse_packet(linktype: i32, data: &[u8]) -> Option<RejectInfo> {
    let (offset, ethertype) = parse_link_layer(linktype, data)?;
    let ip_data = data.get(offset..)?;
    let (local_addr, remote_addr, tcp_offset) = parse_ip(ethertype, ip_data)?;
    let tcp_data = ip_data.get(tcp_offset..)?;
    let (local_port, remote_port) = parse_tcp_rst(tcp_data)?;

    Some(RejectInfo {
        local_addr,
        local_port,
        remote_addr,
        remote_port,
    })
}

/// Parse link-layer header, returning `(offset_to_ip, ethertype)`.
fn parse_link_layer(linktype: i32, data: &[u8]) -> Option<(usize, u16)> {
    match linktype {
        DLT_EN10MB => {
            // Ethernet: 14 bytes, ethertype at bytes 12-13.
            if data.len() < 14 {
                return None;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            Some((14, ethertype))
        }
        DLT_LINUX_SLL => {
            // Linux cooked capture: 16 bytes, protocol at bytes 14-15.
            if data.len() < 16 {
                return None;
            }
            let protocol = u16::from_be_bytes([data[14], data[15]]);
            Some((16, protocol))
        }
        _ => None,
    }
}

/// Parse IP header (v4 or v6), returning `(src_ip, dst_ip, offset_to_tcp)`.
fn parse_ip(ethertype: u16, data: &[u8]) -> Option<(IpAddr, IpAddr, usize)> {
    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(data),
        ETHERTYPE_IPV6 => parse_ipv6(data),
        _ => None,
    }
}

/// Parse IPv4 header. Returns `(src, dst, tcp_header_offset)`.
fn parse_ipv4(data: &[u8]) -> Option<(IpAddr, IpAddr, usize)> {
    if data.len() < 20 {
        return None;
    }
    // IHL is lower 4 bits of first byte, in 32-bit words.
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    // Protocol at offset 9.
    if data[9] != IPPROTO_TCP {
        return None;
    }
    // Source IP at offset 12, dest at 16.
    let src = IpAddr::V4(std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst = IpAddr::V4(std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]));
    Some((src, dst, ihl))
}

/// Parse IPv6 header. Returns `(src, dst, tcp_header_offset)`.
fn parse_ipv6(data: &[u8]) -> Option<(IpAddr, IpAddr, usize)> {
    if data.len() < 40 {
        return None;
    }
    // Next header at offset 6.
    if data[6] != IPPROTO_TCP {
        return None;
    }
    // Source at offset 8 (16 bytes), dest at offset 24 (16 bytes).
    let src_bytes: [u8; 16] = data[8..24].try_into().ok()?;
    let dst_bytes: [u8; 16] = data[24..40].try_into().ok()?;
    let src = IpAddr::V6(std::net::Ipv6Addr::from(src_bytes));
    let dst = IpAddr::V6(std::net::Ipv6Addr::from(dst_bytes));
    Some((src, dst, 40))
}

/// Parse TCP header, verifying RST flag and seq=0.
/// Returns `(src_port, dst_port)` if valid RST with seq=0.
fn parse_tcp_rst(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() < 14 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    // Sequence number at offset 4 (4 bytes).
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    // Flags at offset 13.
    let flags = data[13];
    let rst = flags & 0x04 != 0;

    if rst && seq == 0 {
        Some((src_port, dst_port))
    } else {
        None
    }
}

/// Build a BPF filter string for capturing TCP RST packets from the given addresses.
///
/// Filter: `tcp[tcpflags] & tcp-rst != 0 and tcp[4:4] = 0 and (src host X or src host Y ...)`
pub fn build_bpf_filter(addresses: &[IpAddr]) -> Option<String> {
    if addresses.is_empty() {
        return None;
    }

    let host_clauses: Vec<String> = addresses
        .iter()
        .map(|addr| format!("src host {addr}"))
        .collect();
    let hosts = host_clauses.join(" or ");

    Some(format!(
        "tcp[tcpflags] & tcp-rst != 0 and tcp[4:4] = 0 and ( {hosts} )"
    ))
}

/// Collect IP addresses for a device from pcap's device list.
///
/// If `device_name` is "any", collects addresses from all devices.
/// Otherwise, only from the matching device.
fn device_addresses(device_name: &str) -> Vec<IpAddr> {
    let devices = match pcap::Device::list() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "pcap_findalldevs failed");
            return Vec::new();
        }
    };

    let mut addrs = Vec::new();
    for dev in &devices {
        if device_name != "any" && dev.name != device_name {
            continue;
        }
        for addr in &dev.addresses {
            addrs.push(addr.addr);
        }
    }
    addrs
}

/// Emit a `dionaea.connection.tcp.reject` incident for a captured RST packet.
fn emit_reject(info: &RejectInfo) {
    let info = info.clone();

    let _ = std::thread::spawn(move || {
        pyo3::Python::attach(|py| {
            use pyo3::prelude::*;

            let conn = match pyo3::Py::new(
                py,
                crate::python::connection::PyConnection::for_pcap(
                    "tcp",
                    info.local_addr,
                    info.local_port,
                    info.remote_addr,
                    info.remote_port,
                ),
            ) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "failed to create pcap connection object");
                    return;
                }
            };

            let inc = match pyo3::Py::new(
                py,
                crate::python::incident::PyIncident::new(Some(
                    "dionaea.connection.tcp.reject".to_string(),
                )),
            ) {
                Ok(i) => i,
                Err(e) => {
                    tracing::error!(error = %e, "failed to create tcp.reject incident");
                    return;
                }
            };

            let bound = inc.into_bound(py).into_any();
            if let Err(e) = bound.setattr("con", conn.into_bound(py)) {
                tracing::error!(error = %e, "failed to set incident.con");
                return;
            }
            if let Err(e) = bound.call_method0("report") {
                tracing::error!(error = %e, "failed to report tcp.reject incident");
            }
        });
    })
    .join();
}

/// Capture loop for a single device. Runs until `shutdown` is set.
fn capture_loop(device_name: &str, shutdown: &AtomicBool) {
    let addrs = device_addresses(device_name);
    let Some(filter) = build_bpf_filter(&addrs) else {
        tracing::warn!(device = %device_name, "no addresses found, skipping pcap capture");
        return;
    };

    tracing::info!(device = %device_name, filter = %filter, "starting pcap capture");

    let cap = pcap::Capture::from_device(device_name)
        .map(|c| {
            c.snaplen(SNAPLEN)
                .promisc(device_name != "any")
                .timeout(TIMEOUT_MS)
        })
        .and_then(pcap::Capture::open);

    let mut cap = match cap {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(device = %device_name, error = %e, "failed to open pcap device");
            return;
        }
    };

    if let Err(e) = cap.filter(&filter, true) {
        tracing::error!(device = %device_name, error = %e, "failed to compile BPF filter");
        return;
    }

    let linktype = cap.get_datalink().0;
    match linktype {
        DLT_EN10MB | DLT_LINUX_SLL => {}
        _ => {
            tracing::error!(
                device = %device_name,
                linktype = linktype,
                "unsupported link type"
            );
            return;
        }
    }

    tracing::info!(
        device = %device_name,
        linktype = linktype,
        addresses = addrs.len(),
        "pcap capture active"
    );

    while !shutdown.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(info) = parse_packet(linktype, &packet) {
                    tracing::debug!(
                        local = %info.local_addr,
                        local_port = info.local_port,
                        remote = %info.remote_addr,
                        remote_port = info.remote_port,
                        "tcp reject captured"
                    );
                    emit_reject(&info);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Normal — loop back and check shutdown flag.
            }
            Err(e) => {
                tracing::error!(device = %device_name, error = %e, "pcap capture error");
                break;
            }
        }
    }

    tracing::info!(device = %device_name, "pcap capture stopped");
}

/// Start pcap capture threads for all configured interfaces.
///
/// Returns join handles for graceful shutdown. Set `shutdown` to `true`
/// and join the handles to stop cleanly.
pub fn start(config: &PcapConfig, shutdown: &Arc<AtomicBool>) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    for iface in &config.interfaces {
        let device_name = iface.clone();
        let shutdown = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name(format!("pcap-{device_name}"))
            .spawn(move || {
                capture_loop(&device_name, &shutdown);
            })
            .expect("spawn pcap thread");
        handles.push(handle);
    }

    handles
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- Helper: build an Ethernet + IPv4 + TCP RST packet ---

    fn build_ethernet_ipv4_tcp_rst(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0u8; 6]); // dst mac
        pkt.extend_from_slice(&[0u8; 6]); // src mac
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // ethertype

        // IPv4 header (20 bytes, IHL=5)
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        let total_len: u16 = 40; // 20 IP + 20 TCP
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 4]); // ID, flags, fragment
        pkt.push(64); // TTL
        pkt.push(IPPROTO_TCP); // protocol
        pkt.extend_from_slice(&[0u8; 2]); // checksum
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());

        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // seq = 0
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
        pkt.push(0x50); // data offset = 5 (20 bytes)
        pkt.push(0x04); // flags: RST
        pkt.extend_from_slice(&0u16.to_be_bytes()); // window
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(&0u16.to_be_bytes()); // urgent

        pkt
    }

    fn build_sll_ipv4_tcp_rst(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Linux SLL header (16 bytes)
        pkt.extend_from_slice(&[0u8; 14]); // packet type, ARPHRD, addr len, addr
        pkt.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // protocol

        // IPv4 header (20 bytes)
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 4]);
        pkt.push(64);
        pkt.push(IPPROTO_TCP);
        pkt.extend_from_slice(&[0u8; 2]);
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());

        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt.push(0x50);
        pkt.push(0x04); // RST
        pkt.extend_from_slice(&[0u8; 6]);

        pkt
    }

    fn build_ethernet_ipv6_tcp_rst(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet header
        pkt.extend_from_slice(&[0u8; 12]); // dst + src mac
        pkt.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        // IPv6 header (40 bytes)
        pkt.push(0x60); // version=6
        pkt.extend_from_slice(&[0u8; 3]); // traffic class + flow label
        pkt.extend_from_slice(&20u16.to_be_bytes()); // payload length (TCP header)
        pkt.push(IPPROTO_TCP); // next header
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());

        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // seq = 0
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
        pkt.push(0x50);
        pkt.push(0x04); // RST
        pkt.extend_from_slice(&[0u8; 6]);

        pkt
    }

    // --- parse_packet tests ---

    #[test]
    fn test_parse_ethernet_ipv4_rst() {
        let src: Ipv4Addr = "10.0.0.1".parse().expect("valid");
        let dst: Ipv4Addr = "192.168.1.100".parse().expect("valid");
        let pkt = build_ethernet_ipv4_tcp_rst(src, dst, 80, 54321);

        let info = parse_packet(DLT_EN10MB, &pkt).expect("should parse");
        assert_eq!(info.local_addr, IpAddr::V4(src));
        assert_eq!(info.remote_addr, IpAddr::V4(dst));
        assert_eq!(info.local_port, 80);
        assert_eq!(info.remote_port, 54321);
    }

    #[test]
    fn test_parse_sll_ipv4_rst() {
        let src: Ipv4Addr = "10.0.0.1".parse().expect("valid");
        let dst: Ipv4Addr = "192.168.1.100".parse().expect("valid");
        let pkt = build_sll_ipv4_tcp_rst(src, dst, 445, 12345);

        let info = parse_packet(DLT_LINUX_SLL, &pkt).expect("should parse");
        assert_eq!(info.local_addr, IpAddr::V4(src));
        assert_eq!(info.remote_addr, IpAddr::V4(dst));
        assert_eq!(info.local_port, 445);
        assert_eq!(info.remote_port, 12345);
    }

    #[test]
    fn test_parse_ethernet_ipv6_rst() {
        let src: Ipv6Addr = "2001:db8::1".parse().expect("valid");
        let dst: Ipv6Addr = "2001:db8::2".parse().expect("valid");
        let pkt = build_ethernet_ipv6_tcp_rst(src, dst, 22, 9999);

        let info = parse_packet(DLT_EN10MB, &pkt).expect("should parse");
        assert_eq!(info.local_addr, IpAddr::V6(src));
        assert_eq!(info.remote_addr, IpAddr::V6(dst));
        assert_eq!(info.local_port, 22);
        assert_eq!(info.remote_port, 9999);
    }

    #[test]
    fn test_parse_non_rst_returns_none() {
        let src: Ipv4Addr = "10.0.0.1".parse().expect("valid");
        let dst: Ipv4Addr = "10.0.0.2".parse().expect("valid");
        let mut pkt = build_ethernet_ipv4_tcp_rst(src, dst, 80, 1234);
        // Change flags from RST (0x04) to SYN (0x02).
        // TCP flags are at ethernet(14) + ip(20) + 13 = offset 47.
        pkt[47] = 0x02;
        assert!(parse_packet(DLT_EN10MB, &pkt).is_none());
    }

    #[test]
    fn test_parse_rst_nonzero_seq_returns_none() {
        let src: Ipv4Addr = "10.0.0.1".parse().expect("valid");
        let dst: Ipv4Addr = "10.0.0.2".parse().expect("valid");
        let mut pkt = build_ethernet_ipv4_tcp_rst(src, dst, 80, 1234);
        // Set seq to 1 at ethernet(14) + ip(20) + 4 = offset 38.
        pkt[38] = 0;
        pkt[39] = 0;
        pkt[40] = 0;
        pkt[41] = 1;
        assert!(parse_packet(DLT_EN10MB, &pkt).is_none());
    }

    #[test]
    fn test_parse_non_tcp_returns_none() {
        let src: Ipv4Addr = "10.0.0.1".parse().expect("valid");
        let dst: Ipv4Addr = "10.0.0.2".parse().expect("valid");
        let mut pkt = build_ethernet_ipv4_tcp_rst(src, dst, 80, 1234);
        // Change protocol from TCP (6) to UDP (17) at ethernet(14) + 9 = offset 23.
        pkt[23] = 17;
        assert!(parse_packet(DLT_EN10MB, &pkt).is_none());
    }

    #[test]
    fn test_parse_unknown_linktype_returns_none() {
        let pkt = vec![0u8; 100];
        assert!(parse_packet(999, &pkt).is_none());
    }

    #[test]
    fn test_parse_truncated_packet_returns_none() {
        // Too short for even an Ethernet header.
        assert!(parse_packet(DLT_EN10MB, &[0u8; 10]).is_none());
        // Ethernet header but no IP.
        assert!(parse_packet(DLT_EN10MB, &[0u8; 14]).is_none());
    }

    #[test]
    fn test_parse_unknown_ethertype_returns_none() {
        let mut pkt = vec![0u8; 60];
        // Set ethertype to something unknown (0x9999).
        pkt[12] = 0x99;
        pkt[13] = 0x99;
        assert!(parse_packet(DLT_EN10MB, &pkt).is_none());
    }

    // --- build_bpf_filter tests ---

    #[test]
    fn test_bpf_filter_single_ipv4() {
        let addrs = vec!["10.0.0.1".parse().expect("valid")];
        let filter = build_bpf_filter(&addrs).expect("should produce filter");
        assert_eq!(
            filter,
            "tcp[tcpflags] & tcp-rst != 0 and tcp[4:4] = 0 and ( src host 10.0.0.1 )"
        );
    }

    #[test]
    fn test_bpf_filter_multiple_addresses() {
        let addrs: Vec<IpAddr> = vec![
            "10.0.0.1".parse().expect("valid"),
            "10.0.0.2".parse().expect("valid"),
            "2001:db8::1".parse().expect("valid"),
        ];
        let filter = build_bpf_filter(&addrs).expect("should produce filter");
        assert_eq!(
            filter,
            "tcp[tcpflags] & tcp-rst != 0 and tcp[4:4] = 0 and ( src host 10.0.0.1 or src host 10.0.0.2 or src host 2001:db8::1 )"
        );
    }

    #[test]
    fn test_bpf_filter_empty_returns_none() {
        assert!(build_bpf_filter(&[]).is_none());
    }
}
