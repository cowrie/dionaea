// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
// ABOUTME: TCP/IP personality engine that translates nmap fingerprint fields into packet parameters.
// ABOUTME: Controls TTL, window size, ISN generation, DF bit, TCP options, and ICMP behavior.

//! Personality engine for OS fingerprint simulation.
//!
//! Takes an [`OsFingerprint`] and produces concrete TCP/IP parameters for crafting
//! packets that match the fingerprint. This is the bridge between the nmap-os-db
//! data model and the actual packet construction.

use crate::fingerprint::{OsFingerprint, ProbeResult};
use rand::Rng;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

/// A resolved OS personality ready to drive packet crafting.
///
/// Built from an [`OsFingerprint`], this struct caches the computed values
/// that the TCP/UDP/ICMP handlers need for every packet.
#[derive(Debug, Clone)]
pub struct Personality {
    /// Human-readable name of the emulated OS.
    pub name: String,

    // --- IP layer ---
    /// Default TTL for outgoing packets.
    pub ttl: u8,
    /// Whether to set the Don't Fragment bit on TCP packets.
    pub df: bool,
    /// Whether to set DF on ICMP responses.
    pub df_icmp: bool,

    // --- TCP layer ---
    /// Initial TCP window sizes for SYN-ACK (W1-W6 from WIN line).
    pub window_sizes: [u16; 6],
    /// TCP options to include in SYN-ACK responses (O1-O6 from OPS line).
    pub tcp_options: [Vec<TcpOption>; 6],
    /// ISN (Initial Sequence Number) generation parameters from SEQ line.
    pub isn_params: IsnParams,
    /// TCP timestamp behavior.
    pub timestamp_behavior: TimestampBehavior,

    // --- ECN ---
    /// Whether to respond to ECN probes.
    pub ecn_responds: bool,
    /// ECN probe window size.
    pub ecn_window: u16,
    /// ECN probe TCP options.
    pub ecn_options: Vec<TcpOption>,
    /// ECN congestion control response.
    pub ecn_cc: EcnCc,

    // --- T1-T7 probe responses ---
    /// Pre-computed responses for each T-probe.
    pub t_responses: [Option<TProbeResponse>; 7],

    // --- UDP (U1) ---
    /// Whether to respond to closed-port UDP probes.
    pub udp_responds: bool,
    /// TTL for UDP ICMP unreachable responses.
    pub udp_ttl: u8,
    /// DF bit for UDP ICMP unreachable responses.
    pub udp_df: bool,
    /// IP total length in ICMP unreachable response.
    pub udp_ipl: u16,
    /// Value of UN field (unused bytes in ICMP header).
    pub udp_un: u32,

    // --- ICMP (IE) ---
    /// Whether to respond to ICMP echo probes.
    pub icmp_responds: bool,
    /// ICMP echo DFI (Don't Fragment for ICMP).
    pub icmp_dfi: IcmpDfi,
    /// ICMP Code behavior.
    pub icmp_cd: IcmpCd,
}

/// TCP option types emitted in SYN-ACK packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOption {
    /// Maximum Segment Size.
    Mss(u16),
    /// Window Scale factor.
    WindowScale(u8),
    /// Timestamp (TSval, TSecr).
    Timestamp,
    /// SACK Permitted.
    SackPermitted,
    /// No-Operation (padding).
    Nop,
    /// End of Options List.
    Eol,
}

/// ISN generation parameters derived from the SEQ probe line.
#[derive(Debug, Clone)]
pub struct IsnParams {
    /// SP: Sequence predictability index (0-FF).
    pub sp: u8,
    /// GCD: Greatest Common Divisor of ISN differences.
    pub gcd: u32,
    /// ISR: ISN sequence rate.
    pub isr: u16,
    /// TI: TCP ISN counter behavior (Z=zero, I=incremental, RI=random increment).
    pub ti: IsnBehavior,
}

/// How the ISN counter behaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsnBehavior {
    /// Zero — all ISNs are the same.
    Zero,
    /// Incremental — ISNs increase by a constant or near-constant value.
    Incremental,
    /// Random positive increments.
    RandomIncrement,
    /// Truly random ISN values.
    Random,
}

/// TCP timestamp generation behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampBehavior {
    /// Timestamps not supported.
    None,
    /// Timestamps increase at a known rate.
    Increasing,
    /// Timestamps are unsupported (value U in nmap).
    Unsupported,
}

/// ECN Congestion Control response type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCc {
    /// CC=Y: ECE bit set in response.
    Yes,
    /// CC=N: ECE bit not set.
    No,
    /// CC=S: Both ECE and CWR set.
    Both,
    /// CC=O: Other.
    Other,
}

/// ICMP Don't Fragment behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpDfi {
    /// DF not set on ICMP replies.
    No,
    /// DF set on ICMP replies.
    Yes,
    /// DF echoed from request.
    Echo,
}

/// ICMP Code behavior in echo replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpCd {
    /// CD=Z: Code is zero.
    Zero,
    /// CD=S: Code is same as request.
    Same,
    /// CD=O: Code is non-zero, different from request.
    Other,
}

/// Pre-computed response for a T-probe (T1-T7).
#[derive(Debug, Clone)]
pub struct TProbeResponse {
    /// Whether to respond.
    pub responds: bool,
    /// DF bit.
    pub df: bool,
    /// TTL.
    pub ttl: u8,
    /// Window size.
    pub window: u16,
    /// S field: sequence number behavior.
    pub seq_behavior: SeqBehavior,
    /// A field: acknowledgment behavior.
    pub ack_behavior: AckBehavior,
    /// F field: TCP flags in response.
    pub flags: TcpFlags,
}

/// Sequence number behavior in probe responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqBehavior {
    /// S=Z: Sequence number is zero.
    Zero,
    /// S=A: Seq = ack number from probe.
    EchoAck,
    /// S=A+: Seq = ack number from probe + 1.
    EchoAckPlus,
    /// S=O: Seq is something else (use ISN).
    Other,
}

/// Acknowledgment behavior in probe responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckBehavior {
    /// A=Z: Ack is zero.
    Zero,
    /// A=S: Ack = seq from probe.
    EchoSeq,
    /// A=S+: Ack = seq from probe + 1.
    EchoSeqPlus,
    /// A=O: Ack is something else.
    Other,
}

/// TCP flags for probe responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    /// SYN flag.
    pub syn: bool,
    /// ACK flag.
    pub ack: bool,
    /// RST flag.
    pub rst: bool,
    /// FIN flag.
    pub fin: bool,
    /// PSH flag.
    pub psh: bool,
    /// URG flag.
    pub urg: bool,
    /// ECE flag.
    pub ece: bool,
    /// CWR flag.
    pub cwr: bool,
}

impl TcpFlags {
    /// Parse flags from nmap F= field (e.g. "AS" = ACK+SYN, "AR" = ACK+RST).
    fn from_nmap(s: &str) -> Self {
        let mut flags = TcpFlags {
            syn: false,
            ack: false,
            rst: false,
            fin: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        for c in s.chars() {
            match c {
                'S' => flags.syn = true,
                'A' => flags.ack = true,
                'R' => flags.rst = true,
                'F' => flags.fin = true,
                'P' => flags.psh = true,
                'U' => flags.urg = true,
                'E' => flags.ece = true,
                'W' => flags.cwr = true,
                _ => {}
            }
        }
        flags
    }

    /// Convert to a raw u8 TCP flags byte.
    pub fn to_byte(self) -> u8 {
        let mut b = 0u8;
        if self.fin {
            b |= 0x01;
        }
        if self.syn {
            b |= 0x02;
        }
        if self.rst {
            b |= 0x04;
        }
        if self.psh {
            b |= 0x08;
        }
        if self.ack {
            b |= 0x10;
        }
        if self.urg {
            b |= 0x20;
        }
        if self.ece {
            b |= 0x40;
        }
        if self.cwr {
            b |= 0x80;
        }
        b
    }
}

/// Runtime ISN generator that produces sequence numbers matching the personality.
pub struct IsnGenerator {
    params: IsnParams,
    last_isn: AtomicU32,
    ip_id_counter: AtomicU16,
}

impl IsnGenerator {
    /// Create a new ISN generator for the given personality.
    pub fn new(params: IsnParams) -> Self {
        let mut rng = rand::rng();
        Self {
            params,
            last_isn: AtomicU32::new(rng.random()),
            ip_id_counter: AtomicU16::new(rng.random()),
        }
    }

    /// Generate the next ISN value.
    pub fn next_isn(&self) -> u32 {
        let mut rng = rand::rng();
        let last = self.last_isn.load(Ordering::Relaxed);

        let next = match self.params.ti {
            IsnBehavior::Zero => last,
            IsnBehavior::Incremental => {
                let increment = if self.params.gcd > 1 {
                    self.params.gcd
                } else {
                    // Use ISR to compute approximate increment
                    let rate = u32::from(self.params.isr);
                    rate.wrapping_mul(64)
                };
                last.wrapping_add(increment)
            }
            IsnBehavior::RandomIncrement => {
                let base = if self.params.gcd > 1 {
                    self.params.gcd
                } else {
                    u32::from(self.params.isr).wrapping_mul(64)
                };
                // Random variation around the base increment
                let jitter: u32 = rng.random_range(0..base.max(1));
                last.wrapping_add(base).wrapping_add(jitter)
            }
            IsnBehavior::Random => rng.random(),
        };

        self.last_isn.store(next, Ordering::Relaxed);
        next
    }

    /// Generate the next IP identification value.
    pub fn next_ip_id(&self) -> u16 {
        self.ip_id_counter.fetch_add(1, Ordering::Relaxed)
    }
}

impl Personality {
    /// Build a personality from an nmap OS fingerprint.
    pub fn from_fingerprint(fp: &OsFingerprint) -> Self {
        let (ttl, df) = extract_ttl_df(fp.t_probes[0].as_ref());
        let window_sizes = extract_window_sizes(fp.win.as_ref());
        let tcp_options = extract_tcp_options(fp.ops.as_ref());
        let isn_params = extract_isn_params(fp.seq.as_ref());
        let timestamp_behavior = extract_timestamp_behavior(fp.seq.as_ref());

        let (ecn_responds, ecn_window, ecn_options, ecn_cc) = extract_ecn(fp.ecn.as_ref());

        let mut t_responses: [Option<TProbeResponse>; 7] = [const { None }; 7];
        for (i, probe) in fp.t_probes.iter().enumerate() {
            t_responses[i] = probe.as_ref().map(extract_t_response);
        }

        let (udp_responds, udp_ttl, udp_df, udp_ipl, udp_un) = extract_udp(fp.u1.as_ref());
        let (icmp_responds, icmp_dfi, icmp_cd, df_icmp) = extract_icmp(fp.ie.as_ref());

        Personality {
            name: fp.name.clone(),
            ttl,
            df,
            df_icmp,
            window_sizes,
            tcp_options,
            isn_params,
            timestamp_behavior,
            ecn_responds,
            ecn_window,
            ecn_options,
            ecn_cc,
            t_responses,
            udp_responds,
            udp_ttl,
            udp_df,
            udp_ipl,
            udp_un,
            icmp_responds,
            icmp_dfi,
            icmp_cd,
        }
    }

    /// Get the window size for a given probe index (0-5).
    pub fn window_for_probe(&self, probe_idx: usize) -> u16 {
        self.window_sizes.get(probe_idx).copied().unwrap_or(self.window_sizes[0])
    }

    /// Get TCP options for a given probe index (0-5).
    pub fn options_for_probe(&self, probe_idx: usize) -> &[TcpOption] {
        self.tcp_options
            .get(probe_idx)
            .map(|v| v.as_slice())
            .unwrap_or(&self.tcp_options[0])
    }
}

// --- Extraction helpers ---

fn extract_ttl_df(t1: Option<&ProbeResult>) -> (u8, bool) {
    let Some(t1) = t1 else {
        return (64, true); // Linux default
    };
    let ttl = t1
        .get_hex("TG")
        .or_else(|| t1.get_hex("T"))
        .map(|v| v as u8)
        .unwrap_or(64);
    let df = t1.get("DF").map_or(true, |v| v == "Y");
    (ttl, df)
}

fn extract_window_sizes(win: Option<&ProbeResult>) -> [u16; 6] {
    let Some(win) = win else {
        return [65535; 6];
    };
    let mut sizes = [65535u16; 6];
    for i in 0..6 {
        let key = format!("W{}", i + 1);
        if let Some(v) = win.get_hex(&key) {
            sizes[i] = v as u16;
        }
    }
    sizes
}

fn extract_tcp_options(ops: Option<&ProbeResult>) -> [Vec<TcpOption>; 6] {
    let Some(ops) = ops else {
        return std::array::from_fn(|_| default_tcp_options());
    };
    std::array::from_fn(|i| {
        let key = format!("O{}", i + 1);
        ops.get(&key)
            .map(|s| parse_nmap_options(s))
            .unwrap_or_else(default_tcp_options)
    })
}

fn default_tcp_options() -> Vec<TcpOption> {
    vec![
        TcpOption::Mss(1460),
        TcpOption::Nop,
        TcpOption::WindowScale(7),
        TcpOption::Nop,
        TcpOption::Nop,
        TcpOption::Timestamp,
        TcpOption::SackPermitted,
        TcpOption::Eol,
    ]
}

/// Parse nmap OPS field option string.
///
/// Format: `M54DST11NW7` where:
/// - M followed by hex = MSS (e.g. M54D = MSS 0x54D = 1357)
/// - W followed by hex = Window Scale
/// - T followed by digits = Timestamp options (T0=no TSval, T1=nonzero TSval, T11=both)
/// - N = NOP
/// - S = SACK Permitted
/// - L = EOL
fn parse_nmap_options(s: &str) -> Vec<TcpOption> {
    let mut opts = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            'M' => {
                // MSS: M followed by hex digits
                i += 1;
                let start = i;
                while i < chars.len() && chars[i].is_ascii_hexdigit() {
                    i += 1;
                }
                if start < i {
                    let hex = &s[start..i];
                    if let Ok(val) = u16::from_str_radix(hex, 16) {
                        opts.push(TcpOption::Mss(val));
                    }
                }
            }
            'W' => {
                // Window Scale: W followed by hex digits
                i += 1;
                let start = i;
                while i < chars.len() && chars[i].is_ascii_hexdigit() {
                    i += 1;
                }
                if start < i {
                    let hex = &s[start..i];
                    if let Ok(val) = u8::from_str_radix(hex, 16) {
                        opts.push(TcpOption::WindowScale(val));
                    }
                }
            }
            'T' => {
                // Timestamp
                i += 1;
                // Skip digits that follow T (T0, T1, T11, etc.)
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                opts.push(TcpOption::Timestamp);
            }
            'N' => {
                opts.push(TcpOption::Nop);
                i += 1;
            }
            'S' => {
                opts.push(TcpOption::SackPermitted);
                i += 1;
            }
            'L' => {
                opts.push(TcpOption::Eol);
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    opts
}

fn extract_isn_params(seq: Option<&ProbeResult>) -> IsnParams {
    let Some(seq) = seq else {
        return IsnParams {
            sp: 0xFF,
            gcd: 1,
            isr: 0x100,
            ti: IsnBehavior::RandomIncrement,
        };
    };

    let sp = seq.get_hex("SP").map(|v| v as u8).unwrap_or(0xFF);
    let gcd = seq.get_dec("GCD").unwrap_or(1);
    let isr = seq.get_hex("ISR").map(|v| v as u16).unwrap_or(0x100);
    let ti = match seq.get("TI") {
        Some("Z") => IsnBehavior::Zero,
        Some("I") => IsnBehavior::Incremental,
        Some("RI") => IsnBehavior::RandomIncrement,
        _ => IsnBehavior::RandomIncrement,
    };

    IsnParams { sp, gcd, isr, ti }
}

fn extract_timestamp_behavior(seq: Option<&ProbeResult>) -> TimestampBehavior {
    let Some(seq) = seq else {
        return TimestampBehavior::Increasing;
    };
    match seq.get("TS") {
        Some("U") => TimestampBehavior::Unsupported,
        Some("0") => TimestampBehavior::None,
        _ => TimestampBehavior::Increasing,
    }
}

fn extract_ecn(ecn: Option<&ProbeResult>) -> (bool, u16, Vec<TcpOption>, EcnCc) {
    let Some(ecn) = ecn else {
        return (false, 0, Vec::new(), EcnCc::No);
    };
    let responds = ecn.responds();
    let window = ecn.get_hex("W").map(|v| v as u16).unwrap_or(0);
    let options = ecn
        .get("O")
        .map(|s| parse_nmap_options(s))
        .unwrap_or_default();
    let cc = match ecn.get("CC") {
        Some("Y") => EcnCc::Yes,
        Some("N") => EcnCc::No,
        Some("S") => EcnCc::Both,
        _ => EcnCc::Other,
    };
    (responds, window, options, cc)
}

fn extract_t_response(probe: &ProbeResult) -> TProbeResponse {
    let responds = probe.responds();
    if !responds {
        return TProbeResponse {
            responds: false,
            df: false,
            ttl: 0,
            window: 0,
            seq_behavior: SeqBehavior::Zero,
            ack_behavior: AckBehavior::Zero,
            flags: TcpFlags::from_nmap(""),
        };
    }

    let df = probe.get("DF").map_or(false, |v| v == "Y");
    let ttl = probe
        .get_hex("TG")
        .or_else(|| probe.get_hex("T"))
        .map(|v| v as u8)
        .unwrap_or(64);
    let window = probe.get_hex("W").map(|v| v as u16).unwrap_or(0);

    let seq_behavior = match probe.get("S") {
        Some("Z") => SeqBehavior::Zero,
        Some("A") => SeqBehavior::EchoAck,
        Some("A+") => SeqBehavior::EchoAckPlus,
        Some("O") => SeqBehavior::Other,
        _ => SeqBehavior::Other,
    };

    let ack_behavior = match probe.get("A") {
        Some("Z") => AckBehavior::Zero,
        Some("S") => AckBehavior::EchoSeq,
        Some("S+") => AckBehavior::EchoSeqPlus,
        Some("O") => AckBehavior::Other,
        _ => AckBehavior::Other,
    };

    let flags = probe
        .get("F")
        .map(|s| TcpFlags::from_nmap(s))
        .unwrap_or_else(|| TcpFlags::from_nmap(""));

    TProbeResponse {
        responds,
        df,
        ttl,
        window,
        seq_behavior,
        ack_behavior,
        flags,
    }
}

fn extract_udp(u1: Option<&ProbeResult>) -> (bool, u8, bool, u16, u32) {
    let Some(u1) = u1 else {
        return (true, 64, false, 0x164, 0);
    };
    let responds = u1.responds();
    let ttl = u1
        .get_hex("TG")
        .or_else(|| u1.get_hex("T"))
        .map(|v| v as u8)
        .unwrap_or(64);
    let df = u1.get("DF").map_or(false, |v| v == "Y");
    let ipl = u1.get_hex("IPL").map(|v| v as u16).unwrap_or(0x164);
    let un = u1.get_hex("UN").unwrap_or(0);
    (responds, ttl, df, ipl, un)
}

fn extract_icmp(ie: Option<&ProbeResult>) -> (bool, IcmpDfi, IcmpCd, bool) {
    let Some(ie) = ie else {
        return (true, IcmpDfi::No, IcmpCd::Zero, false);
    };
    let responds = ie.responds();
    let dfi = match ie.get("DFI") {
        Some("Y") => IcmpDfi::Yes,
        Some("N") => IcmpDfi::No,
        Some("S") => IcmpDfi::Echo,
        _ => IcmpDfi::No,
    };
    let cd = match ie.get("CD") {
        Some("Z") => IcmpCd::Zero,
        Some("S") => IcmpCd::Same,
        _ => IcmpCd::Other,
    };
    let df_icmp = matches!(dfi, IcmpDfi::Yes);
    (responds, dfi, cd, df_icmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::FingerprintDb;

    const SAMPLE_DB: &str = r#"
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

Fingerprint Windows 10 (1903)
Class Microsoft | Windows | 10 | general purpose
SEQ(SP=FF%GCD=1%ISR=10C%TI=I%CI=I%II=I%TS=U)
OPS(O1=M54DNW8NNS%O2=M54DNW8NNS%O3=M54DNW8%O4=M54DNW8NNS%O5=M54DNW8NNS%O6=M54DNNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%T=80%TG=80%W=FFFF%O=M54DNW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=80%TG=80%W=0%S=A%A=O%F=R%RD=0%Q=)
T5(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=S+%F=AR%RD=0%Q=)
T6(R=Y%DF=Y%T=80%TG=80%W=0%S=A%A=O%F=R%RD=0%Q=)
T7(R=Y%DF=Y%T=80%TG=80%W=0%S=Z%A=S+%F=AR%RD=0%Q=)
U1(R=Y%DF=N%T=80%TG=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%TG=80%CD=Z)
"#;

    #[test]
    fn test_linux_personality() {
        let db = FingerprintDb::parse(SAMPLE_DB).expect("parse");
        let fp = db.find_by_name("Linux").expect("found");
        let p = Personality::from_fingerprint(fp);

        assert_eq!(p.name, "Linux 3.2 - 4.9");
        assert_eq!(p.ttl, 64); // 0x40
        assert!(p.df);
        assert_eq!(p.window_sizes[0], 0xFE88);
        assert_eq!(p.isn_params.ti, IsnBehavior::Zero);
        assert!(p.ecn_responds);
        assert_eq!(p.ecn_cc, EcnCc::Yes);
    }

    #[test]
    fn test_windows_personality() {
        let db = FingerprintDb::parse(SAMPLE_DB).expect("parse");
        let fp = db.find_by_name("Windows 10").expect("found");
        let p = Personality::from_fingerprint(fp);

        assert_eq!(p.ttl, 128); // 0x80
        assert!(p.df);
        assert_eq!(p.window_sizes[0], 0xFFFF);
        assert_eq!(p.window_sizes[5], 0xFF70);
        assert_eq!(p.isn_params.ti, IsnBehavior::Incremental);
        assert_eq!(p.timestamp_behavior, TimestampBehavior::Unsupported);
    }

    #[test]
    fn test_t_probe_responses() {
        let db = FingerprintDb::parse(SAMPLE_DB).expect("parse");
        let fp = db.find_by_name("Linux").expect("found");
        let p = Personality::from_fingerprint(fp);

        // T1: responds with SYN-ACK
        let t1 = p.t_responses[0].as_ref().expect("T1");
        assert!(t1.responds);
        assert!(t1.df);
        assert_eq!(t1.ttl, 64);
        assert!(t1.flags.syn);
        assert!(t1.flags.ack);
        assert_eq!(t1.seq_behavior, SeqBehavior::Other); // S=O
        assert_eq!(t1.ack_behavior, AckBehavior::EchoSeqPlus); // A=S+

        // T2: does not respond
        let t2 = p.t_responses[1].as_ref().expect("T2");
        assert!(!t2.responds);

        // T5: RST+ACK
        let t5 = p.t_responses[4].as_ref().expect("T5");
        assert!(t5.responds);
        assert!(t5.flags.ack);
        assert!(t5.flags.rst);
        assert_eq!(t5.seq_behavior, SeqBehavior::Zero);
        assert_eq!(t5.ack_behavior, AckBehavior::EchoSeqPlus);
    }

    #[test]
    fn test_isn_generator() {
        let params = IsnParams {
            sp: 0xFF,
            gcd: 1,
            isr: 0x100,
            ti: IsnBehavior::RandomIncrement,
        };
        let isn_gen = IsnGenerator::new(params);
        let isn1 = isn_gen.next_isn();
        let isn2 = isn_gen.next_isn();
        // Random increments should produce different values
        // (technically could collide but astronomically unlikely)
        assert_ne!(isn1, isn2);
    }

    #[test]
    fn test_isn_zero_behavior() {
        let params = IsnParams {
            sp: 0,
            gcd: 1,
            isr: 0,
            ti: IsnBehavior::Zero,
        };
        let isn_gen = IsnGenerator::new(params);
        let isn1 = isn_gen.next_isn();
        let isn2 = isn_gen.next_isn();
        assert_eq!(isn1, isn2);
    }

    #[test]
    fn test_tcp_flags_parse() {
        let flags = TcpFlags::from_nmap("AS");
        assert!(flags.ack);
        assert!(flags.syn);
        assert!(!flags.rst);
        assert!(!flags.fin);

        let flags = TcpFlags::from_nmap("AR");
        assert!(flags.ack);
        assert!(flags.rst);
        assert!(!flags.syn);

        let flags = TcpFlags::from_nmap("R");
        assert!(flags.rst);
        assert!(!flags.ack);
    }

    #[test]
    fn test_tcp_flags_to_byte() {
        let flags = TcpFlags::from_nmap("AS");
        let b = flags.to_byte();
        assert_eq!(b & 0x02, 0x02); // SYN
        assert_eq!(b & 0x10, 0x10); // ACK
    }

    #[test]
    fn test_parse_nmap_options() {
        let opts = parse_nmap_options("M54DST11NW7");
        assert!(opts.iter().any(|o| matches!(o, TcpOption::Mss(0x54D))));
        assert!(opts.iter().any(|o| matches!(o, TcpOption::SackPermitted)));
        assert!(opts.iter().any(|o| matches!(o, TcpOption::Timestamp)));
        assert!(opts.iter().any(|o| matches!(o, TcpOption::Nop)));
        assert!(opts.iter().any(|o| matches!(o, TcpOption::WindowScale(7))));
    }

    #[test]
    fn test_udp_personality() {
        let db = FingerprintDb::parse(SAMPLE_DB).expect("parse");
        let fp = db.find_by_name("Linux").expect("found");
        let p = Personality::from_fingerprint(fp);

        assert!(p.udp_responds);
        assert!(!p.udp_df);
        assert_eq!(p.udp_ttl, 64);
        assert_eq!(p.udp_ipl, 0x164);
        assert_eq!(p.udp_un, 0);
    }

    #[test]
    fn test_icmp_personality() {
        let db = FingerprintDb::parse(SAMPLE_DB).expect("parse");

        let linux = db.find_by_name("Linux").expect("found");
        let p = Personality::from_fingerprint(linux);
        assert!(p.icmp_responds);
        assert_eq!(p.icmp_dfi, IcmpDfi::No);
        assert_eq!(p.icmp_cd, IcmpCd::Same); // CD=S

        let win = db.find_by_name("Windows 10").expect("found");
        let p = Personality::from_fingerprint(win);
        assert!(p.icmp_responds);
        assert_eq!(p.icmp_cd, IcmpCd::Zero); // CD=Z
    }
}
