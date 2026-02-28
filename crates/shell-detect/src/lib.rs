// ABOUTME: Shellcode detection via GetPC byte pattern scanning.
// ABOUTME: Detects x86, x86-64, and MIPS shellcode in arbitrary byte streams.

/// Scan a byte buffer for shellcode GetPC patterns.
///
/// Returns the offset and architecture of any detected shellcode,
/// or `None` if no patterns match.
pub fn detect(_data: &[u8]) -> Option<Detection> {
    // Placeholder - will be implemented in Phase 5
    None
}

/// A detected shellcode pattern.
pub struct Detection {
    /// Byte offset where the pattern was found.
    pub offset: usize,
    /// CPU architecture of the detected shellcode.
    pub arch: Arch,
}

/// CPU architecture for shellcode detection.
pub enum Arch {
    /// x86 32-bit
    X86,
    /// x86 64-bit
    X64,
    /// MIPS
    Mips,
}
