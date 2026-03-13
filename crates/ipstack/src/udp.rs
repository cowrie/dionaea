// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: UDP probe response handler for nmap U1 test simulation.
// ABOUTME: Sends ICMP Port Unreachable for closed ports with personality-matched parameters.

//! UDP handler for the custom IP stack.
//!
//! Handles incoming UDP packets. For closed ports, generates ICMP Port
//! Unreachable responses with personality-driven parameters (TTL, DF,
//! IP total length, unused header bytes) matching the nmap U1 test.

use crate::packet::{self, ParsedIpv4, ParsedUdp};
use crate::personality::{IsnGenerator, Personality};
use std::collections::HashSet;

/// UDP handler manages open ports and generates appropriate responses.
pub struct UdpHandler {
    /// Ports that have UDP services (no ICMP unreachable for these).
    open_ports: HashSet<u16>,
    /// Personality for crafting ICMP responses.
    personality: Personality,
    /// ISN generator (shared with TCP for IP ID generation).
    isn_gen: IsnGenerator,
}

/// Events from the UDP handler.
#[derive(Debug)]
pub enum UdpEvent {
    /// Data received on an open UDP port.
    DataReceived {
        /// Source IP.
        src_ip: [u8; 4],
        /// Source port.
        src_port: u16,
        /// Destination IP.
        dst_ip: [u8; 4],
        /// Destination port.
        dst_port: u16,
        /// Payload.
        data: Vec<u8>,
    },
}

impl UdpHandler {
    /// Create a new UDP handler with the given personality.
    pub fn new(personality: Personality) -> Self {
        let isn_gen = IsnGenerator::new(personality.isn_params.clone());
        UdpHandler {
            open_ports: HashSet::new(),
            personality,
            isn_gen,
        }
    }

    /// Mark a port as open (UDP service running).
    pub fn open_port(&mut self, port: u16) {
        self.open_ports.insert(port);
    }

    /// Mark a port as closed.
    pub fn close_port(&mut self, port: u16) {
        self.open_ports.remove(&port);
    }

    /// Process an incoming UDP packet. Returns response packet (if any) and events.
    pub fn handle_packet(
        &self,
        ip: &ParsedIpv4,
        udp: &ParsedUdp,
        raw_packet: &[u8],
    ) -> (Option<Vec<u8>>, Vec<UdpEvent>) {
        let mut events = Vec::new();
        let udp_data = &raw_packet[ip.payload_offset..];

        if self.open_ports.contains(&udp.dst_port) {
            // Open port — deliver data to application
            let payload = udp.payload(udp_data);
            events.push(UdpEvent::DataReceived {
                src_ip: ip.src_ip,
                src_port: udp.src_port,
                dst_ip: ip.dst_ip,
                dst_port: udp.dst_port,
                data: payload.to_vec(),
            });
            return (None, events);
        }

        // Closed port — send ICMP Port Unreachable if personality says so
        if !self.personality.udp_responds {
            return (None, events);
        }

        let ip_header = ip.header(raw_packet);
        let icmp_pkt = packet::build_icmp_port_unreachable(
            ip.dst_ip,
            ip.src_ip,
            ip_header,
            udp_data,
            &self.personality,
            &self.isn_gen,
        );

        (Some(icmp_pkt), events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::FingerprintDb;

    fn make_handler() -> UdpHandler {
        let db = FingerprintDb::parse(
            r#"
Fingerprint Linux 3.2 - 4.9
Class Linux | Linux | 3.X | general purpose
SEQ(SP=F9%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
T1(R=Y%DF=Y%T=40%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
U1(R=Y%DF=N%T=40%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%TG=40%CD=S)
"#,
        )
        .expect("parse");
        let fp = db.find_by_name("Linux").expect("found");
        let p = Personality::from_fingerprint(fp);
        UdpHandler::new(p)
    }

    fn make_udp_packet(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let udp_len = 8 + 4; // header + 4 bytes payload
        let ip_total = 20 + udp_len;
        let mut pkt = vec![0u8; ip_total];

        // IPv4 header
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);

        // UDP header
        let udp = &mut pkt[20..];
        udp[0..2].copy_from_slice(&src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        // payload
        udp[8..12].copy_from_slice(b"test");

        pkt
    }

    #[test]
    fn test_closed_port_sends_icmp_unreachable() {
        let handler = make_handler();
        let pkt = make_udp_packet([10, 0, 0, 2], [10, 0, 0, 1], 12345, 9999);

        let ip = ParsedIpv4::parse(&pkt).expect("ip");
        let udp_data = ip.payload(&pkt);
        let udp = ParsedUdp::parse(udp_data).expect("udp");

        let (resp, events) = handler.handle_packet(&ip, &udp, &pkt);
        assert!(resp.is_some(), "should send ICMP");
        assert!(events.is_empty());

        let icmp_pkt = resp.expect("icmp");
        let icmp_ip = ParsedIpv4::parse(&icmp_pkt).expect("icmp ip");
        assert_eq!(icmp_ip.protocol, 1); // ICMP
        assert_eq!(icmp_ip.ttl, 64); // Linux TTL

        let icmp_data = icmp_ip.payload(&icmp_pkt);
        assert_eq!(icmp_data[0], 3); // Dest Unreachable
        assert_eq!(icmp_data[1], 3); // Port Unreachable
    }

    #[test]
    fn test_open_port_delivers_data() {
        let mut handler = make_handler();
        handler.open_port(53);

        let pkt = make_udp_packet([10, 0, 0, 2], [10, 0, 0, 1], 12345, 53);
        let ip = ParsedIpv4::parse(&pkt).expect("ip");
        let udp_data = ip.payload(&pkt);
        let udp = ParsedUdp::parse(udp_data).expect("udp");

        let (resp, events) = handler.handle_packet(&ip, &udp, &pkt);
        assert!(resp.is_none(), "open port should not send ICMP");
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], UdpEvent::DataReceived { dst_port: 53, .. }));
    }
}
