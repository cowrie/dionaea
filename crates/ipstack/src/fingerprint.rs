// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial
// ABOUTME: Parser for the nmap-os-db fingerprint database file format.
// ABOUTME: Extracts OS personality definitions used to simulate TCP/IP stack behavior.

//! Nmap OS fingerprint database parser.
//!
//! Parses the `nmap-os-db` file format into structured [`OsFingerprint`] records.
//! Each fingerprint contains probe response lines (SEQ, OPS, WIN, ECN, T1-T7, U1, IE)
//! that define how a particular OS responds to nmap's OS detection probes.
//!
//! Reference: <https://nmap.org/book/osdetect-fingerprint-format.html>

use std::collections::HashMap;
use std::path::Path;

/// A complete OS fingerprint entry from nmap-os-db.
#[derive(Debug, Clone)]
pub struct OsFingerprint {
    /// Human-readable fingerprint name (e.g. "Linux 2.6.32 - 3.13").
    pub name: String,
    /// OS class lines (vendor|family|generation|device_type).
    pub classes: Vec<OsClass>,
    /// Sequence generation analysis parameters.
    pub seq: Option<ProbeResult>,
    /// TCP options from the six SEQ probes.
    pub ops: Option<ProbeResult>,
    /// TCP window sizes from the six SEQ probes.
    pub win: Option<ProbeResult>,
    /// ECN (Explicit Congestion Notification) probe response.
    pub ecn: Option<ProbeResult>,
    /// TCP probe responses T1 through T7.
    pub t_probes: [Option<ProbeResult>; 7],
    /// UDP probe response.
    pub u1: Option<ProbeResult>,
    /// ICMP echo probe response.
    pub ie: Option<ProbeResult>,
}

/// OS classification metadata.
#[derive(Debug, Clone)]
pub struct OsClass {
    /// Vendor name (e.g. "Linux", "Microsoft").
    pub vendor: String,
    /// OS family (e.g. "Linux", "Windows").
    pub os_family: String,
    /// OS generation (e.g. "2.6.X", "10").
    pub os_gen: String,
    /// Device type (e.g. "general purpose", "router").
    pub device_type: String,
}

/// Key-value pairs from a single probe result line.
///
/// Each line looks like: `T1(R=Y%DF=Y%T=40%TG=40%S=O%A=S+%F=AS%RD=0%Q=)`
#[derive(Debug, Clone, Default)]
pub struct ProbeResult {
    /// Raw key-value fields parsed from the probe line.
    pub fields: HashMap<String, String>,
}

impl ProbeResult {
    /// Get a field value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }

    /// Get a field as a hex integer. Supports decimal and hex (no prefix).
    pub fn get_hex(&self, key: &str) -> Option<u32> {
        let val = self.get(key)?;
        if val.is_empty() {
            return None;
        }
        u32::from_str_radix(val, 16).ok()
    }

    /// Get a field as a decimal integer.
    pub fn get_dec(&self, key: &str) -> Option<u32> {
        let val = self.get(key)?;
        val.parse().ok()
    }

    /// Check if `R=Y` (target responds).
    pub fn responds(&self) -> bool {
        self.get("R").is_none_or(|v| v == "Y")
    }
}

/// A database of parsed OS fingerprints.
#[derive(Debug, Clone)]
pub struct FingerprintDb {
    /// All fingerprints in the database.
    pub fingerprints: Vec<OsFingerprint>,
}

impl FingerprintDb {
    /// Load fingerprints from an nmap-os-db file.
    pub fn load(path: &Path) -> Result<Self, FingerprintError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| FingerprintError::Io(format!("failed to read {}: {e}", path.display())))?;
        Self::parse(&content)
    }

    /// Parse fingerprints from a string containing nmap-os-db format data.
    pub fn parse(content: &str) -> Result<Self, FingerprintError> {
        let mut fingerprints = Vec::new();
        let mut current: Option<OsFingerprintBuilder> = None;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and blank lines
            if line.is_empty() || line.starts_with('#') {
                // A blank line after a fingerprint block finalizes it
                if line.is_empty() {
                    if let Some(builder) = current.take() {
                        fingerprints.push(builder.build());
                    }
                }
                continue;
            }

            if let Some(name) = line.strip_prefix("Fingerprint ") {
                // Start of a new fingerprint block
                if let Some(builder) = current.take() {
                    fingerprints.push(builder.build());
                }
                current = Some(OsFingerprintBuilder::new(name.to_string()));
            } else if let Some(class_line) = line.strip_prefix("Class ") {
                if let Some(ref mut builder) = current {
                    if let Some(class) = parse_class(class_line) {
                        builder.classes.push(class);
                    }
                }
            } else if let Some(cpe_line) = line.strip_prefix("CPE ") {
                // CPE lines are informational; we skip them
                let _ = cpe_line;
            } else if let Some((category, probe_str)) = line.split_once('(') {
                // Probe result line: CATEGORY(key=val%key=val%...)
                if let Some(ref mut builder) = current {
                    let probe_str = probe_str.trim_end_matches(')');
                    let probe = parse_probe_fields(probe_str);
                    builder.set_probe(category, probe);
                }
            }
        }

        // Don't forget the last fingerprint
        if let Some(builder) = current.take() {
            fingerprints.push(builder.build());
        }

        Ok(FingerprintDb { fingerprints })
    }

    /// Find a fingerprint by name (case-insensitive substring match).
    pub fn find_by_name(&self, query: &str) -> Option<&OsFingerprint> {
        let query_lower = query.to_lowercase();
        self.fingerprints
            .iter()
            .find(|fp| fp.name.to_lowercase().contains(&query_lower))
    }

    /// Find all fingerprints matching an OS family.
    pub fn find_by_family(&self, family: &str) -> Vec<&OsFingerprint> {
        let family_lower = family.to_lowercase();
        self.fingerprints
            .iter()
            .filter(|fp| {
                fp.classes
                    .iter()
                    .any(|c| c.os_family.to_lowercase() == family_lower)
            })
            .collect()
    }

    /// Number of fingerprints in the database.
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }
}

/// Builder for accumulating fingerprint lines.
struct OsFingerprintBuilder {
    name: String,
    classes: Vec<OsClass>,
    seq: Option<ProbeResult>,
    ops: Option<ProbeResult>,
    win: Option<ProbeResult>,
    ecn: Option<ProbeResult>,
    t_probes: [Option<ProbeResult>; 7],
    u1: Option<ProbeResult>,
    ie: Option<ProbeResult>,
}

impl OsFingerprintBuilder {
    fn new(name: String) -> Self {
        Self {
            name,
            classes: Vec::new(),
            seq: None,
            ops: None,
            win: None,
            ecn: None,
            t_probes: [const { None }; 7],
            u1: None,
            ie: None,
        }
    }

    fn set_probe(&mut self, category: &str, probe: ProbeResult) {
        match category {
            "SEQ" => self.seq = Some(probe),
            "OPS" => self.ops = Some(probe),
            "WIN" => self.win = Some(probe),
            "ECN" => self.ecn = Some(probe),
            "T1" => self.t_probes[0] = Some(probe),
            "T2" => self.t_probes[1] = Some(probe),
            "T3" => self.t_probes[2] = Some(probe),
            "T4" => self.t_probes[3] = Some(probe),
            "T5" => self.t_probes[4] = Some(probe),
            "T6" => self.t_probes[5] = Some(probe),
            "T7" => self.t_probes[6] = Some(probe),
            "U1" => self.u1 = Some(probe),
            "IE" => self.ie = Some(probe),
            _ => {} // Unknown category, skip
        }
    }

    fn build(self) -> OsFingerprint {
        OsFingerprint {
            name: self.name,
            classes: self.classes,
            seq: self.seq,
            ops: self.ops,
            win: self.win,
            ecn: self.ecn,
            t_probes: self.t_probes,
            u1: self.u1,
            ie: self.ie,
        }
    }
}

/// Parse a `Class` line: `vendor | family | generation | device_type`
fn parse_class(line: &str) -> Option<OsClass> {
    let parts: Vec<&str> = line.splitn(4, '|').collect();
    if parts.len() < 4 {
        return None;
    }
    Some(OsClass {
        vendor: parts[0].trim().to_string(),
        os_family: parts[1].trim().to_string(),
        os_gen: parts[2].trim().to_string(),
        device_type: parts[3].trim().to_string(),
    })
}

/// Parse probe fields from `key=val%key=val%...` format.
fn parse_probe_fields(s: &str) -> ProbeResult {
    let mut fields = HashMap::new();
    if s.is_empty() {
        return ProbeResult { fields };
    }
    for pair in s.split('%') {
        if let Some((key, val)) = pair.split_once('=') {
            fields.insert(key.to_string(), val.to_string());
        }
    }
    ProbeResult { fields }
}

/// Errors from fingerprint parsing.
#[derive(Debug)]
pub enum FingerprintError {
    /// I/O error reading the fingerprint file.
    Io(String),
    /// Parse error in the fingerprint data.
    Parse(String),
}

impl std::fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FingerprintError::Io(msg) => write!(f, "fingerprint I/O error: {msg}"),
            FingerprintError::Parse(msg) => write!(f, "fingerprint parse error: {msg}"),
        }
    }
}

impl std::error::Error for FingerprintError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_FINGERPRINT: &str = r#"
# Nmap OS fingerprint database

Fingerprint Linux 3.2 - 4.9
Class Linux | Linux | 3.X | general purpose
Class Linux | Linux | 4.X | general purpose
CPE cpe:/o:linux:linux_kernel:3 auto
CPE cpe:/o:linux:linux_kernel:4 auto
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
CPE cpe:/o:microsoft:windows_10 auto
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
    fn test_parse_sample_db() {
        let db = FingerprintDb::parse(SAMPLE_FINGERPRINT).expect("parse");
        assert_eq!(db.len(), 2);

        let linux = &db.fingerprints[0];
        assert_eq!(linux.name, "Linux 3.2 - 4.9");
        assert_eq!(linux.classes.len(), 2);
        assert_eq!(linux.classes[0].os_family, "Linux");
        assert_eq!(linux.classes[0].os_gen, "3.X");
        assert_eq!(linux.classes[1].os_gen, "4.X");

        // Check SEQ line parsed correctly
        let seq = linux.seq.as_ref().expect("SEQ");
        assert_eq!(seq.get("SP"), Some("F9"));
        assert_eq!(seq.get("GCD"), Some("1"));
        assert_eq!(seq.get("TI"), Some("Z"));

        // Check WIN line
        let win = linux.win.as_ref().expect("WIN");
        assert_eq!(win.get("W1"), Some("FE88"));
        assert_eq!(win.get_hex("W1"), Some(0xFE88));

        // Check T1
        let t1 = linux.t_probes[0].as_ref().expect("T1");
        assert!(t1.responds());
        assert_eq!(t1.get("DF"), Some("Y"));
        assert_eq!(t1.get("T"), Some("40"));
        assert_eq!(t1.get("S"), Some("O"));
        assert_eq!(t1.get("F"), Some("AS"));

        // Check T2 (no response)
        let t2 = linux.t_probes[1].as_ref().expect("T2");
        assert!(!t2.responds());
    }

    #[test]
    fn test_find_by_name() {
        let db = FingerprintDb::parse(SAMPLE_FINGERPRINT).expect("parse");
        let fp = db.find_by_name("Windows 10").expect("found");
        assert!(fp.name.contains("Windows 10"));

        let not_found = db.find_by_name("FreeBSD");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_find_by_family() {
        let db = FingerprintDb::parse(SAMPLE_FINGERPRINT).expect("parse");
        let linux = db.find_by_family("Linux");
        assert_eq!(linux.len(), 1);
        assert!(linux[0].name.contains("Linux"));

        let windows = db.find_by_family("Windows");
        assert_eq!(windows.len(), 1);
    }

    #[test]
    fn test_windows_fingerprint_ttl() {
        let db = FingerprintDb::parse(SAMPLE_FINGERPRINT).expect("parse");
        let win = db.find_by_name("Windows 10").expect("found");

        // Windows uses TTL 128 (0x80)
        let t1 = win.t_probes[0].as_ref().expect("T1");
        assert_eq!(t1.get_hex("T"), Some(0x80));
        assert_eq!(t1.get_hex("TG"), Some(0x80));

        // Linux uses TTL 64 (0x40)
        let linux = db.find_by_name("Linux 3.2").expect("found");
        let t1 = linux.t_probes[0].as_ref().expect("T1");
        assert_eq!(t1.get_hex("T"), Some(0x40));
    }

    #[test]
    fn test_parse_class() {
        let class = parse_class("Microsoft | Windows | 10 | general purpose").expect("class");
        assert_eq!(class.vendor, "Microsoft");
        assert_eq!(class.os_family, "Windows");
        assert_eq!(class.os_gen, "10");
        assert_eq!(class.device_type, "general purpose");
    }

    #[test]
    fn test_parse_empty() {
        let db = FingerprintDb::parse("").expect("empty parse");
        assert!(db.is_empty());
    }

    #[test]
    fn test_parse_comments_only() {
        let db = FingerprintDb::parse("# comment\n# another\n").expect("comments");
        assert!(db.is_empty());
    }

    #[test]
    fn test_u1_probe_fields() {
        let db = FingerprintDb::parse(SAMPLE_FINGERPRINT).expect("parse");
        let linux = &db.fingerprints[0];
        let u1 = linux.u1.as_ref().expect("U1");
        assert!(u1.responds());
        assert_eq!(u1.get("DF"), Some("N"));
        assert_eq!(u1.get("IPL"), Some("164"));
        assert_eq!(u1.get("RIPL"), Some("G"));
        assert_eq!(u1.get("RUCK"), Some("G"));
    }

    #[test]
    fn test_ie_probe_fields() {
        let db = FingerprintDb::parse(SAMPLE_FINGERPRINT).expect("parse");
        let linux = &db.fingerprints[0];
        let ie = linux.ie.as_ref().expect("IE");
        assert!(ie.responds());
        assert_eq!(ie.get("CD"), Some("S"));

        let win = &db.fingerprints[1];
        let ie = win.ie.as_ref().expect("IE");
        assert_eq!(ie.get("CD"), Some("Z"));
    }
}
