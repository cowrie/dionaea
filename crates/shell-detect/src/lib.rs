// SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
// SPDX-License-Identifier: AGPL-3.0-only
//! ABOUTME: Shellcode detection via `GetPC` byte pattern scanning.
//! ABOUTME: Detects x86, x86-64, and MIPS shellcode in arbitrary byte streams.

/// Scan a byte buffer for shellcode `GetPC` patterns.
///
/// Returns the offset and architecture of any detected shellcode,
/// or `None` if no patterns match.
pub fn detect(data: &[u8]) -> Option<Detection> {
    // x86: call $+5; pop reg  (E8 00 00 00 00 [58-5F])
    if let Some(offset) = find_x86_call_pop(data) {
        return Some(Detection {
            offset,
            arch: Arch::X86,
        });
    }

    // x86: FPU GetPC  (D9 EE D9 74 24 F4)
    if let Some(offset) = find_x86_fpu(data) {
        return Some(Detection {
            offset,
            arch: Arch::X86,
        });
    }

    // x86: jmp over; call back  (EB xx E8 yy yy yy yy [58-5F])
    if let Some(offset) = find_x86_jmp_call(data) {
        return Some(Detection {
            offset,
            arch: Arch::X86,
        });
    }

    // x86-64: RIP-relative lea  (48 8D 05 00 00 00 00)
    if let Some(offset) = find_x64_lea_rip(data) {
        return Some(Detection {
            offset,
            arch: Arch::X64,
        });
    }

    // MIPS: BGEZAL $zero, $-4  (04 11 FF FF)
    if let Some(offset) = find_mips_bgezal(data) {
        return Some(Detection {
            offset,
            arch: Arch::Mips,
        });
    }

    None
}

/// x86 `call $+5; pop reg` pattern.
///
/// `E8 00 00 00 00` is `call` with displacement 0 (calls the next instruction).
/// Followed by `pop` of any general register (`58`=`eax` through `5F`=`edi`).
fn find_x86_call_pop(data: &[u8]) -> Option<usize> {
    if data.len() < 6 {
        return None;
    }
    for i in 0..=data.len() - 6 {
        if data[i] == 0xE8
            && data[i + 1] == 0x00
            && data[i + 2] == 0x00
            && data[i + 3] == 0x00
            && data[i + 4] == 0x00
            && (0x58..=0x5F).contains(&data[i + 5])
        {
            return Some(i);
        }
    }
    None
}

/// x86 FPU `GetPC` pattern.
///
/// `D9 EE` = `fldz` (push 0.0 on FPU stack)
/// `D9 74 24 F4` = `fnstenv [esp-12]` (store FPU environment on stack)
/// The stored FPU environment includes the EIP of the last FPU instruction.
fn find_x86_fpu(data: &[u8]) -> Option<usize> {
    const PATTERN: [u8; 6] = [0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4];
    if data.len() < PATTERN.len() {
        return None;
    }
    for i in 0..=data.len() - PATTERN.len() {
        if data[i..i + PATTERN.len()] == PATTERN {
            return Some(i);
        }
    }
    None
}

/// x86 jmp-over-call `GetPC` pattern.
///
/// `EB xx` = short jmp (xx bytes forward)
/// At the jmp target: `E8 yy yy yy yy` = call back, followed by pop reg.
/// The call pushes the return address (= address after call) onto the stack.
fn find_x86_jmp_call(data: &[u8]) -> Option<usize> {
    if data.len() < 3 {
        return None;
    }
    for i in 0..=data.len() - 3 {
        if data[i] != 0xEB {
            continue;
        }
        let jmp_offset = data[i + 1] as usize;
        // The call instruction is at i + 2 + jmp_offset
        let call_pos = i + 2 + jmp_offset;
        // Need call (5 bytes) + pop (1 byte)
        if call_pos + 6 > data.len() {
            continue;
        }
        if data[call_pos] == 0xE8 && (0x58..=0x5F).contains(&data[call_pos + 5]) {
            return Some(i);
        }
    }
    None
}

/// x86-64 RIP-relative lea pattern.
///
/// `48 8D 05 00 00 00 00` = `lea rax, [rip+0]`
/// `REX.W` prefix (48) + `LEA` opcode (8D) + `ModRM` for `[rip+disp32]` with `rax` (05)
/// displacement 0 means it loads the address of the next instruction.
fn find_x64_lea_rip(data: &[u8]) -> Option<usize> {
    const PATTERN: [u8; 7] = [0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00];
    if data.len() < PATTERN.len() {
        return None;
    }
    for i in 0..=data.len() - PATTERN.len() {
        if data[i..i + PATTERN.len()] == PATTERN {
            return Some(i);
        }
    }
    None
}

/// MIPS `BGEZAL $zero` `GetPC` pattern.
///
/// `04 11 FF FF` = `bgezal $zero, -4`
/// $zero is always >= 0, so this always branches-and-links.
/// The link register ($ra) gets the address of the instruction after the
/// branch delay slot, giving the shellcode its own address.
fn find_mips_bgezal(data: &[u8]) -> Option<usize> {
    const PATTERN: [u8; 4] = [0x04, 0x11, 0xFF, 0xFF];
    if data.len() < PATTERN.len() {
        return None;
    }
    for i in 0..=data.len() - PATTERN.len() {
        if data[i..i + PATTERN.len()] == PATTERN {
            return Some(i);
        }
    }
    None
}

/// A detected shellcode pattern.
#[derive(Debug)]
pub struct Detection {
    /// Byte offset where the pattern was found.
    pub offset: usize,
    /// CPU architecture of the detected shellcode.
    pub arch: Arch,
}

/// CPU architecture for shellcode detection.
#[derive(Debug, PartialEq, Eq)]
pub enum Arch {
    /// x86 32-bit
    X86,
    /// x86 64-bit
    X64,
    /// MIPS
    Mips,
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::X86 => write!(f, "x86"),
            Arch::X64 => write!(f, "x86-64"),
            Arch::Mips => write!(f, "mips"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- x86 call $+5; pop reg ---

    #[test]
    fn x86_call_pop_eax() {
        // call $+5; pop eax
        let data = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x58];
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 0);
        assert_eq!(det.arch, Arch::X86);
    }

    #[test]
    fn x86_call_pop_edi() {
        // call $+5; pop edi (5F = last valid pop)
        let data = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x5F];
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 0);
        assert_eq!(det.arch, Arch::X86);
    }

    #[test]
    fn x86_call_pop_with_prefix() {
        // Some garbage before the pattern
        let mut data = vec![0x90, 0x90, 0xCC]; // nop nop int3
        data.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B]); // pop ebx
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 3);
        assert_eq!(det.arch, Arch::X86);
    }

    #[test]
    fn x86_call_pop_invalid_pop_byte() {
        // E8 00 00 00 00 60 — 0x60 is pusha, not pop
        let data = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x60];
        assert!(detect(&data).is_none());
    }

    // --- x86 FPU GetPC ---

    #[test]
    fn x86_fpu_getpc() {
        let data = [0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4];
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 0);
        assert_eq!(det.arch, Arch::X86);
    }

    #[test]
    fn x86_fpu_getpc_embedded() {
        let mut data = vec![0x41, 0x42, 0x43];
        data.extend_from_slice(&[0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4]);
        data.extend_from_slice(&[0x90, 0x90]);
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 3);
        assert_eq!(det.arch, Arch::X86);
    }

    // --- x86 jmp+call ---

    #[test]
    fn x86_jmp_call() {
        // EB 02 = jmp +2 (skip 2 bytes of padding)
        // pad pad
        // E8 xx xx xx xx pop_eax
        let mut data = vec![0xEB, 0x02, 0x90, 0x90];
        data.extend_from_slice(&[0xE8, 0xF9, 0xFF, 0xFF, 0xFF, 0x58]);
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 0);
        assert_eq!(det.arch, Arch::X86);
    }

    #[test]
    fn x86_jmp_call_no_pop() {
        // Same as above but without the pop register byte matching
        let mut data = vec![0xEB, 0x02, 0x90, 0x90];
        data.extend_from_slice(&[0xE8, 0xF9, 0xFF, 0xFF, 0xFF, 0x60]); // 0x60 = pusha
        assert!(detect(&data).is_none());
    }

    // --- x86-64 RIP-relative lea ---

    #[test]
    fn x64_lea_rip() {
        let data = [0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00];
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 0);
        assert_eq!(det.arch, Arch::X64);
    }

    #[test]
    fn x64_lea_rip_with_prefix() {
        let mut data = vec![0xCC, 0xCC];
        data.extend_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 2);
        assert_eq!(det.arch, Arch::X64);
    }

    // --- MIPS BGEZAL ---

    #[test]
    fn mips_bgezal() {
        let data = [0x04, 0x11, 0xFF, 0xFF];
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 0);
        assert_eq!(det.arch, Arch::Mips);
    }

    #[test]
    fn mips_bgezal_embedded() {
        let mut data = vec![0x00; 10];
        data.extend_from_slice(&[0x04, 0x11, 0xFF, 0xFF]);
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 10);
        assert_eq!(det.arch, Arch::Mips);
    }

    // --- Edge cases ---

    #[test]
    fn empty_data() {
        assert!(detect(&[]).is_none());
    }

    #[test]
    fn too_short_for_any_pattern() {
        assert!(detect(&[0xE8, 0x00]).is_none());
    }

    #[test]
    fn no_shellcode_in_normal_data() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(detect(data).is_none());
    }

    #[test]
    fn priority_returns_first_match() {
        // Both x86 call+pop and FPU pattern present — call+pop comes first
        let mut data = vec![0xE8, 0x00, 0x00, 0x00, 0x00, 0x58];
        data.extend_from_slice(&[0xD9, 0xEE, 0xD9, 0x74, 0x24, 0xF4]);
        let det = detect(&data).expect("should detect");
        assert_eq!(det.offset, 0);
        assert_eq!(det.arch, Arch::X86);
    }

    #[test]
    fn arch_display() {
        assert_eq!(Arch::X86.to_string(), "x86");
        assert_eq!(Arch::X64.to_string(), "x86-64");
        assert_eq!(Arch::Mips.to_string(), "mips");
    }
}
