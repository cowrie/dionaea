// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: ICMP echo request/reply handler for nmap IE test simulation.
// ABOUTME: Crafts echo replies with personality-matched TTL, DF, and code behavior.

//! ICMP handler for the custom IP stack.
//!
//! Responds to ICMP Echo Requests with personality-driven Echo Replies
//! that match the nmap IE probe test. Controls DF bit behavior (DFI field),
//! ICMP code behavior (CD field), and TTL.

use crate::packet::{self, ParsedIcmp, ParsedIpv4};
use crate::personality::{IsnGenerator, Personality};

/// ICMP handler with personality-driven responses.
pub struct IcmpHandler {
    /// Personality controlling response parameters.
    personality: Personality,
    /// ISN generator for IP ID values.
    isn_gen: IsnGenerator,
}

impl IcmpHandler {
    /// Create a new ICMP handler.
    pub fn new(personality: Personality) -> Self {
        let isn_gen = IsnGenerator::new(personality.isn_params.clone());
        IcmpHandler {
            personality,
            isn_gen,
        }
    }

    /// Process an incoming ICMP packet. Returns a response packet if applicable.
    pub fn handle_packet(
        &self,
        ip: &ParsedIpv4,
        icmp: &ParsedIcmp,
        raw_icmp: &[u8],
    ) -> Option<Vec<u8>> {
        if !icmp.is_echo_request() {
            return None;
        }

        if !self.personality.icmp_responds {
            return None;
        }

        let echo_data = icmp.echo_data(raw_icmp);

        Some(packet::build_icmp_echo_reply(
            ip.dst_ip,
            ip.src_ip,
            icmp.id,
            icmp.seq,
            echo_data,
            &self.personality,
            &self.isn_gen,
            ip.df,
            icmp.code,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::FingerprintDb;

    fn make_handler(db_str: &str, name: &str) -> IcmpHandler {
        let db = FingerprintDb::parse(db_str).expect("parse");
        let fp = db.find_by_name(name).expect("found");
        let p = Personality::from_fingerprint(fp);
        IcmpHandler::new(p)
    }

    const DB: &str = r#"
Fingerprint Linux 3.2 - 4.9
Class Linux | Linux | 3.X | general purpose
SEQ(SP=F9%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
T1(R=Y%DF=Y%T=40%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
U1(R=Y%DF=N%T=40%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%TG=40%CD=S)

Fingerprint Windows 10 (1903)
Class Microsoft | Windows | 10 | general purpose
SEQ(SP=FF%GCD=1%ISR=10C%TI=I%CI=I%II=I%TS=U)
T1(R=Y%DF=Y%T=80%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
U1(R=Y%DF=N%T=80%TG=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%TG=80%CD=Z)
"#;

    fn make_echo_request(src_ip: [u8; 4], dst_ip: [u8; 4], df: bool) -> Vec<u8> {
        let icmp_len = 8 + 4; // header + 4 bytes data
        let ip_total = 20 + icmp_len;
        let mut pkt = vec![0u8; ip_total];

        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        let flags_frag = if df { 0x4000u16 } else { 0x0000u16 };
        pkt[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);

        // ICMP Echo Request
        let icmp = &mut pkt[20..];
        icmp[0] = 8; // Echo Request
        icmp[1] = 9; // Nonstandard code (for testing CD behavior)
        icmp[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        icmp[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        icmp[8..12].copy_from_slice(b"ping");

        pkt
    }

    #[test]
    fn test_linux_echo_reply() {
        let handler = make_handler(DB, "Linux");
        let pkt = make_echo_request([10, 0, 0, 2], [10, 0, 0, 1], false);

        let ip = ParsedIpv4::parse(&pkt).expect("ip");
        let icmp_data = ip.payload(&pkt);
        let icmp = ParsedIcmp::parse(icmp_data).expect("icmp");

        let resp = handler.handle_packet(&ip, &icmp, icmp_data);
        assert!(resp.is_some());

        let reply = resp.expect("reply");
        let reply_ip = ParsedIpv4::parse(&reply).expect("reply ip");
        assert_eq!(reply_ip.ttl, 64); // Linux TTL
        assert!(!reply_ip.df); // DFI=N

        let reply_icmp_data = reply_ip.payload(&reply);
        let reply_icmp = ParsedIcmp::parse(reply_icmp_data).expect("reply icmp");
        assert_eq!(reply_icmp.icmp_type, 0); // Echo Reply
        assert_eq!(reply_icmp.code, 9); // CD=S: echoes the request code
        assert_eq!(reply_icmp.id, 0x1234);
        assert_eq!(reply_icmp.seq, 0x0001);
    }

    #[test]
    fn test_windows_echo_reply_code_zero() {
        let handler = make_handler(DB, "Windows");
        let pkt = make_echo_request([10, 0, 0, 2], [10, 0, 0, 1], false);

        let ip = ParsedIpv4::parse(&pkt).expect("ip");
        let icmp_data = ip.payload(&pkt);
        let icmp = ParsedIcmp::parse(icmp_data).expect("icmp");

        let resp = handler.handle_packet(&ip, &icmp, icmp_data);
        let reply = resp.expect("reply");
        let reply_ip = ParsedIpv4::parse(&reply).expect("reply ip");
        assert_eq!(reply_ip.ttl, 128); // Windows TTL

        let reply_icmp_data = reply_ip.payload(&reply);
        let reply_icmp = ParsedIcmp::parse(reply_icmp_data).expect("reply icmp");
        assert_eq!(reply_icmp.code, 0); // CD=Z: always zero
    }

    #[test]
    fn test_non_echo_request_ignored() {
        let handler = make_handler(DB, "Linux");
        // Build a non-echo ICMP (type 3 = Dest Unreachable)
        let mut pkt = make_echo_request([10, 0, 0, 2], [10, 0, 0, 1], false);
        pkt[20] = 3; // Change type to Dest Unreachable

        let ip = ParsedIpv4::parse(&pkt).expect("ip");
        let icmp_data = ip.payload(&pkt);
        let icmp = ParsedIcmp::parse(icmp_data).expect("icmp");

        let resp = handler.handle_packet(&ip, &icmp, icmp_data);
        assert!(resp.is_none());
    }
}
