// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: Raw IPv4/TCP/UDP/ICMP packet construction with personality-driven parameters.
// ABOUTME: Builds wire-format packets suitable for injection via TUN device.

//! Packet construction utilities for the custom IP stack.
//!
//! All functions produce complete IP packets (header + payload) ready to be
//! written to a TUN device. The personality engine controls TTL, DF, window
//! size, TCP options, and other stack-identifying fields.

use crate::personality::{Personality, TcpOption, IsnGenerator, TcpFlags};

/// IPv4 protocol numbers.
pub const PROTO_ICMP: u8 = 1;
/// TCP protocol number.
pub const PROTO_TCP: u8 = 6;
/// UDP protocol number.
pub const PROTO_UDP: u8 = 17;

/// Build a TCP SYN-ACK response packet with personality-driven parameters.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_synack(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    personality: &Personality,
    isn_gen: &IsnGenerator,
    probe_idx: usize,
) -> Vec<u8> {
    let window = personality.window_for_probe(probe_idx);
    let options = personality.options_for_probe(probe_idx);
    let flags = TcpFlags {
        syn: true,
        ack: true,
        rst: false,
        fin: false,
        psh: false,
        urg: false,
        ece: false,
        cwr: false,
    };

    build_tcp_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq_num,
        ack_num,
        window,
        flags,
        options,
        &[],
        personality.ttl,
        personality.df,
        isn_gen.next_ip_id(),
    )
}

/// Build a TCP RST response packet.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_rst(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    personality: &Personality,
    isn_gen: &IsnGenerator,
) -> Vec<u8> {
    let flags = TcpFlags {
        syn: false,
        ack: true,
        rst: true,
        fin: false,
        psh: false,
        urg: false,
        ece: false,
        cwr: false,
    };

    build_tcp_packet(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq_num,
        ack_num,
        0,
        flags,
        &[],
        &[],
        personality.ttl,
        personality.df,
        isn_gen.next_ip_id(),
    )
}

/// Build a generic TCP packet with arbitrary flags and options.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    window: u16,
    flags: TcpFlags,
    options: &[TcpOption],
    payload: &[u8],
    ttl: u8,
    df: bool,
    ip_id: u16,
) -> Vec<u8> {
    // Serialize TCP options
    let opts_bytes = serialize_tcp_options(options);
    let tcp_header_len = 20 + opts_bytes.len();
    // Pad to 4-byte boundary
    let tcp_header_len_padded = (tcp_header_len + 3) & !3;
    let data_offset = (tcp_header_len_padded / 4) as u8;

    let tcp_total = tcp_header_len_padded + payload.len();
    let ip_total = 20 + tcp_total;

    let mut pkt = vec![0u8; ip_total];

    // --- IPv4 header (20 bytes) ---
    write_ipv4_header(
        &mut pkt,
        ip_total as u16,
        ip_id,
        df,
        ttl,
        PROTO_TCP,
        src_ip,
        dst_ip,
    );

    // --- TCP header ---
    let tcp = &mut pkt[20..];
    // Source port
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    // Destination port
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    // Sequence number
    tcp[4..8].copy_from_slice(&seq_num.to_be_bytes());
    // Acknowledgment number
    tcp[8..12].copy_from_slice(&ack_num.to_be_bytes());
    // Data offset (4 bits) + reserved (4 bits)
    tcp[12] = data_offset << 4;
    // Flags
    tcp[13] = flags.to_byte();
    // Window
    tcp[14..16].copy_from_slice(&window.to_be_bytes());
    // Checksum (placeholder, computed below)
    tcp[16..18].copy_from_slice(&[0, 0]);
    // Urgent pointer
    tcp[18..20].copy_from_slice(&[0, 0]);

    // TCP options
    if !opts_bytes.is_empty() {
        tcp[20..20 + opts_bytes.len()].copy_from_slice(&opts_bytes);
    }
    // Pad with NOPs to reach data_offset
    for byte in tcp[20 + opts_bytes.len()..tcp_header_len_padded].iter_mut() {
        *byte = 0; // NOP padding (EOL would also work)
    }

    // Payload
    if !payload.is_empty() {
        pkt[20 + tcp_header_len_padded..20 + tcp_header_len_padded + payload.len()]
            .copy_from_slice(payload);
    }

    // TCP checksum (pseudo-header + TCP header + payload)
    let tcp_checksum = compute_tcp_checksum(&pkt[20..], src_ip, dst_ip, tcp_total as u16);
    pkt[20 + 16] = (tcp_checksum >> 8) as u8;
    pkt[20 + 17] = (tcp_checksum & 0xFF) as u8;

    // IP header checksum
    let ip_checksum = compute_ip_checksum(&pkt[0..20]);
    pkt[10] = (ip_checksum >> 8) as u8;
    pkt[11] = (ip_checksum & 0xFF) as u8;

    pkt
}

/// Build an ICMP Echo Reply packet.
pub fn build_icmp_echo_reply(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    id: u16,
    seq: u16,
    data: &[u8],
    personality: &Personality,
    isn_gen: &IsnGenerator,
    request_df: bool,
    request_code: u8,
) -> Vec<u8> {
    use crate::personality::{IcmpDfi, IcmpCd};

    let df = match personality.icmp_dfi {
        IcmpDfi::Yes => true,
        IcmpDfi::No => false,
        IcmpDfi::Echo => request_df,
    };

    let code = match personality.icmp_cd {
        IcmpCd::Zero => 0,
        IcmpCd::Same => request_code,
        IcmpCd::Other => 1,
    };

    let icmp_len = 8 + data.len();
    let ip_total = 20 + icmp_len;
    let mut pkt = vec![0u8; ip_total];

    write_ipv4_header(
        &mut pkt,
        ip_total as u16,
        isn_gen.next_ip_id(),
        df,
        personality.ttl,
        PROTO_ICMP,
        src_ip,
        dst_ip,
    );

    // ICMP header
    let icmp = &mut pkt[20..];
    icmp[0] = 0; // Type: Echo Reply
    icmp[1] = code;
    icmp[2..4].copy_from_slice(&[0, 0]); // Checksum placeholder
    icmp[4..6].copy_from_slice(&id.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq.to_be_bytes());

    // Echo data
    if !data.is_empty() {
        icmp[8..8 + data.len()].copy_from_slice(data);
    }

    // ICMP checksum
    let cksum = compute_icmp_checksum(&pkt[20..]);
    pkt[20 + 2] = (cksum >> 8) as u8;
    pkt[20 + 3] = (cksum & 0xFF) as u8;

    // IP checksum
    let ip_cksum = compute_ip_checksum(&pkt[0..20]);
    pkt[10] = (ip_cksum >> 8) as u8;
    pkt[11] = (ip_cksum & 0xFF) as u8;

    pkt
}

/// Build an ICMP Destination Unreachable (Port Unreachable) response for UDP probes.
pub fn build_icmp_port_unreachable(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    original_ip_header: &[u8],
    original_payload: &[u8],
    personality: &Personality,
    isn_gen: &IsnGenerator,
) -> Vec<u8> {
    // ICMP Dest Unreachable: 8 bytes ICMP header + original IP header + 8 bytes of original payload
    let quoted_len = original_ip_header.len().min(60) + original_payload.len().min(8);
    let icmp_len = 8 + quoted_len;
    let ip_total = 20 + icmp_len;
    let mut pkt = vec![0u8; ip_total];

    write_ipv4_header(
        &mut pkt,
        ip_total as u16,
        isn_gen.next_ip_id(),
        personality.udp_df,
        personality.udp_ttl,
        PROTO_ICMP,
        src_ip,
        dst_ip,
    );

    // ICMP header
    let icmp = &mut pkt[20..];
    icmp[0] = 3; // Type: Destination Unreachable
    icmp[1] = 3; // Code: Port Unreachable
    icmp[2..4].copy_from_slice(&[0, 0]); // Checksum placeholder
    // Unused field (4 bytes) — UN field from personality
    icmp[4..8].copy_from_slice(&personality.udp_un.to_be_bytes());

    // Quote original IP header
    let ip_hdr_len = original_ip_header.len().min(60);
    icmp[8..8 + ip_hdr_len].copy_from_slice(&original_ip_header[..ip_hdr_len]);

    // Quote first 8 bytes of original payload
    let payload_quote_len = original_payload.len().min(8);
    icmp[8 + ip_hdr_len..8 + ip_hdr_len + payload_quote_len]
        .copy_from_slice(&original_payload[..payload_quote_len]);

    // ICMP checksum
    let cksum = compute_icmp_checksum(&pkt[20..]);
    pkt[20 + 2] = (cksum >> 8) as u8;
    pkt[20 + 3] = (cksum & 0xFF) as u8;

    // IP checksum
    let ip_cksum = compute_ip_checksum(&pkt[0..20]);
    pkt[10] = (ip_cksum >> 8) as u8;
    pkt[11] = (ip_cksum & 0xFF) as u8;

    pkt
}

/// Write the IPv4 header into the first 20 bytes of `buf`.
fn write_ipv4_header(
    buf: &mut [u8],
    total_length: u16,
    id: u16,
    df: bool,
    ttl: u8,
    protocol: u8,
    src: [u8; 4],
    dst: [u8; 4],
) {
    buf[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    buf[1] = 0x00; // DSCP/ECN
    buf[2..4].copy_from_slice(&total_length.to_be_bytes());
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    // Flags + Fragment Offset
    let flags_frag = if df { 0x4000u16 } else { 0x0000u16 };
    buf[6..8].copy_from_slice(&flags_frag.to_be_bytes());
    buf[8] = ttl;
    buf[9] = protocol;
    buf[10..12].copy_from_slice(&[0, 0]); // Checksum placeholder
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
}

/// Serialize TCP options to bytes.
fn serialize_tcp_options(options: &[TcpOption]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40);

    for opt in options {
        match opt {
            TcpOption::Mss(val) => {
                buf.push(2); // Kind
                buf.push(4); // Length
                buf.extend_from_slice(&val.to_be_bytes());
            }
            TcpOption::WindowScale(val) => {
                buf.push(3); // Kind
                buf.push(3); // Length
                buf.push(*val);
            }
            TcpOption::Timestamp => {
                buf.push(8); // Kind
                buf.push(10); // Length
                // TSval: current timestamp-like value
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| (d.as_millis() / 10) as u32)
                    .unwrap_or(0);
                buf.extend_from_slice(&ts.to_be_bytes());
                // TSecr: 0 for SYN-ACK (will be set per-connection later)
                buf.extend_from_slice(&0u32.to_be_bytes());
            }
            TcpOption::SackPermitted => {
                buf.push(4); // Kind
                buf.push(2); // Length
            }
            TcpOption::Nop => {
                buf.push(1); // Kind
            }
            TcpOption::Eol => {
                buf.push(0); // Kind
            }
        }
    }

    buf
}

/// Compute the Internet Checksum (RFC 1071) over a byte slice.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute IP header checksum.
fn compute_ip_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

/// Compute TCP checksum including the pseudo-header.
fn compute_tcp_checksum(tcp_segment: &[u8], src_ip: [u8; 4], dst_ip: [u8; 4], tcp_len: u16) -> u16 {
    // Build pseudo-header
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(PROTO_TCP);
    pseudo.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo.extend_from_slice(tcp_segment);
    internet_checksum(&pseudo)
}

/// Compute ICMP checksum.
fn compute_icmp_checksum(icmp_data: &[u8]) -> u16 {
    internet_checksum(icmp_data)
}

/// Parse an incoming IPv4 packet and extract key fields.
#[derive(Debug)]
pub struct ParsedIpv4 {
    /// IP version (should be 4).
    pub version: u8,
    /// Header length in bytes.
    pub ihl: usize,
    /// Total length.
    pub total_length: u16,
    /// Identification.
    pub id: u16,
    /// Don't Fragment flag.
    pub df: bool,
    /// More Fragments flag.
    pub mf: bool,
    /// Fragment offset.
    pub frag_offset: u16,
    /// Time To Live.
    pub ttl: u8,
    /// Protocol number.
    pub protocol: u8,
    /// Source IP.
    pub src_ip: [u8; 4],
    /// Destination IP.
    pub dst_ip: [u8; 4],
    /// Offset into the packet where the payload starts.
    pub payload_offset: usize,
}

impl ParsedIpv4 {
    /// Parse an IPv4 header from raw bytes. Returns None if too short or not IPv4.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let version = data[0] >> 4;
        if version != 4 {
            return None;
        }
        let ihl = ((data[0] & 0x0F) as usize) * 4;
        if data.len() < ihl {
            return None;
        }

        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let id = u16::from_be_bytes([data[4], data[5]]);
        let flags_frag = u16::from_be_bytes([data[6], data[7]]);
        let df = (flags_frag & 0x4000) != 0;
        let mf = (flags_frag & 0x2000) != 0;
        let frag_offset = flags_frag & 0x1FFF;

        let mut src_ip = [0u8; 4];
        let mut dst_ip = [0u8; 4];
        src_ip.copy_from_slice(&data[12..16]);
        dst_ip.copy_from_slice(&data[16..20]);

        Some(ParsedIpv4 {
            version,
            ihl,
            total_length,
            id,
            df,
            mf,
            frag_offset,
            ttl: data[8],
            protocol: data[9],
            src_ip,
            dst_ip,
            payload_offset: ihl,
        })
    }

    /// Get the payload portion of the packet.
    pub fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        let end = (self.total_length as usize).min(data.len());
        if self.payload_offset < end {
            &data[self.payload_offset..end]
        } else {
            &[]
        }
    }

    /// Get the raw IP header bytes.
    pub fn header<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[..self.ihl.min(data.len())]
    }
}

/// Parsed TCP header fields.
#[derive(Debug)]
pub struct ParsedTcp {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq_num: u32,
    /// Acknowledgment number.
    pub ack_num: u32,
    /// Data offset (header length in 4-byte words).
    pub data_offset: u8,
    /// Raw flags byte.
    pub flags: u8,
    /// Window size.
    pub window: u16,
    /// Payload offset within the TCP segment.
    pub payload_offset: usize,
}

impl ParsedTcp {
    /// Parse a TCP header from the IP payload.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let data_offset = (data[12] >> 4) as usize;
        let header_len = data_offset * 4;

        Some(ParsedTcp {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset: data_offset as u8,
            flags: data[13],
            window: u16::from_be_bytes([data[14], data[15]]),
            payload_offset: header_len,
        })
    }

    /// Check if SYN flag is set.
    pub fn is_syn(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Check if ACK flag is set.
    pub fn is_ack(&self) -> bool {
        self.flags & 0x10 != 0
    }

    /// Check if RST flag is set.
    pub fn is_rst(&self) -> bool {
        self.flags & 0x04 != 0
    }

    /// Check if FIN flag is set.
    pub fn is_fin(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Check if PSH flag is set.
    pub fn is_psh(&self) -> bool {
        self.flags & 0x08 != 0
    }

    /// Check if this is a SYN-only packet (no ACK).
    pub fn is_syn_only(&self) -> bool {
        self.is_syn() && !self.is_ack()
    }

    /// Get the payload portion of the TCP segment.
    pub fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        if self.payload_offset < data.len() {
            &data[self.payload_offset..]
        } else {
            &[]
        }
    }
}

/// Parsed UDP header.
#[derive(Debug)]
pub struct ParsedUdp {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Length (header + payload).
    pub length: u16,
}

impl ParsedUdp {
    /// Parse a UDP header from the IP payload.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(ParsedUdp {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
        })
    }

    /// Get the payload (data after 8-byte UDP header).
    pub fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        if data.len() > 8 {
            &data[8..]
        } else {
            &[]
        }
    }
}

/// Parsed ICMP header.
#[derive(Debug)]
pub struct ParsedIcmp {
    /// ICMP type.
    pub icmp_type: u8,
    /// ICMP code.
    pub code: u8,
    /// Identifier (for echo request/reply).
    pub id: u16,
    /// Sequence number (for echo request/reply).
    pub seq: u16,
}

impl ParsedIcmp {
    /// Parse an ICMP header from the IP payload.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(ParsedIcmp {
            icmp_type: data[0],
            code: data[1],
            id: u16::from_be_bytes([data[4], data[5]]),
            seq: u16::from_be_bytes([data[6], data[7]]),
        })
    }

    /// Is this an Echo Request (type 8)?
    pub fn is_echo_request(&self) -> bool {
        self.icmp_type == 8
    }

    /// Get the echo data (after 8-byte ICMP header).
    pub fn echo_data<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        if data.len() > 8 {
            &data[8..]
        } else {
            &[]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::FingerprintDb;

    fn linux_personality() -> Personality {
        let db = FingerprintDb::parse(
            r#"
Fingerprint Linux 3.2 - 4.9
Class Linux | Linux | 3.X | general purpose
SEQ(SP=F9%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%T=40%TG=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%TG=40%W=0%S=A%A=Z%F=R%RD=0%Q=)
T5(R=Y%DF=Y%T=40%TG=40%W=0%S=Z%A=S+%F=AR%RD=0%Q=)
T6(R=Y%DF=Y%T=40%TG=40%W=0%S=A%A=Z%F=R%RD=0%Q=)
T7(R=Y%DF=Y%T=40%TG=40%W=0%S=Z%A=S+%F=AR%RD=0%Q=)
U1(R=Y%DF=N%T=40%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%TG=40%CD=S)
"#,
        )
        .expect("parse");
        let fp = db.find_by_name("Linux").expect("found");
        Personality::from_fingerprint(fp)
    }

    #[test]
    fn test_build_tcp_synack_valid_ipv4() {
        let p = linux_personality();
        let isn_gen = IsnGenerator::new(p.isn_params.clone());
        let pkt = build_tcp_synack(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            80,
            12345,
            1000,
            2001,
            &p,
            &isn_gen,
            0,
        );

        // Parse the packet back
        let ip = ParsedIpv4::parse(&pkt).expect("valid IPv4");
        assert_eq!(ip.version, 4);
        assert_eq!(ip.protocol, PROTO_TCP);
        assert_eq!(ip.src_ip, [10, 0, 0, 1]);
        assert_eq!(ip.dst_ip, [10, 0, 0, 2]);
        assert_eq!(ip.ttl, 64); // Linux TTL
        assert!(ip.df); // Linux sets DF

        let tcp_data = ip.payload(&pkt);
        let tcp = ParsedTcp::parse(tcp_data).expect("valid TCP");
        assert_eq!(tcp.src_port, 80);
        assert_eq!(tcp.dst_port, 12345);
        assert!(tcp.is_syn());
        assert!(tcp.is_ack());
        assert_eq!(tcp.window, 0xFE88); // Linux window
    }

    #[test]
    fn test_build_tcp_rst_valid() {
        let p = linux_personality();
        let isn_gen = IsnGenerator::new(p.isn_params.clone());
        let pkt = build_tcp_rst(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            80,
            12345,
            0,
            1001,
            &p,
            &isn_gen,
        );

        let ip = ParsedIpv4::parse(&pkt).expect("valid IPv4");
        let tcp_data = ip.payload(&pkt);
        let tcp = ParsedTcp::parse(tcp_data).expect("valid TCP");
        assert!(tcp.is_rst());
        assert!(tcp.is_ack());
        assert_eq!(tcp.window, 0);
    }

    #[test]
    fn test_ipv4_checksum_valid() {
        let p = linux_personality();
        let isn_gen = IsnGenerator::new(p.isn_params.clone());
        let pkt = build_tcp_synack(
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            443,
            54321,
            0,
            1,
            &p,
            &isn_gen,
            0,
        );

        // Verify IP checksum: should be zero when computed over the header
        let cksum = internet_checksum(&pkt[0..20]);
        assert_eq!(cksum, 0);
    }

    #[test]
    fn test_parse_ipv4_too_short() {
        assert!(ParsedIpv4::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_tcp_too_short() {
        assert!(ParsedTcp::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_icmp_echo_reply() {
        let p = linux_personality();
        let isn_gen = IsnGenerator::new(p.isn_params.clone());
        let data = b"echo test data";
        let pkt = build_icmp_echo_reply(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            0x1234,
            0x0001,
            data,
            &p,
            &isn_gen,
            false,
            0,
        );

        let ip = ParsedIpv4::parse(&pkt).expect("valid IPv4");
        assert_eq!(ip.protocol, PROTO_ICMP);
        assert_eq!(ip.ttl, 64);
        assert!(!ip.df); // Linux ICMP DFI=N

        let icmp_data = ip.payload(&pkt);
        let icmp = ParsedIcmp::parse(icmp_data).expect("valid ICMP");
        assert_eq!(icmp.icmp_type, 0); // Echo Reply
        assert_eq!(icmp.id, 0x1234);
        assert_eq!(icmp.seq, 0x0001);

        // Verify ICMP checksum
        let cksum = internet_checksum(icmp_data);
        assert_eq!(cksum, 0);
    }

    #[test]
    fn test_icmp_port_unreachable() {
        let p = linux_personality();
        let isn_gen = IsnGenerator::new(p.isn_params.clone());

        // Fake original IP header (20 bytes)
        let orig_ip = [0x45, 0, 0, 28, 0, 1, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 2, 10, 0, 0, 1];
        let orig_payload = [0u8; 8]; // 8 bytes UDP header

        let pkt = build_icmp_port_unreachable(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &orig_ip,
            &orig_payload,
            &p,
            &isn_gen,
        );

        let ip = ParsedIpv4::parse(&pkt).expect("valid IPv4");
        assert_eq!(ip.protocol, PROTO_ICMP);

        let icmp_data = ip.payload(&pkt);
        assert_eq!(icmp_data[0], 3); // Dest Unreachable
        assert_eq!(icmp_data[1], 3); // Port Unreachable
    }
}
