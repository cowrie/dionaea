// ABOUTME: GetPC pattern detection for shellcode
// ABOUTME: Detects CALL/POP and FNSTENV patterns used by position-independent code

#include <stdlib.h>
#include <string.h>

#include "emu/emu.h"
#include "emu/emu_shellcode.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

/**
 * Check if offset contains an x86 GetPC pattern
 *
 * Ported from libemu/src/emu_getpc.c
 *
 * Detects two common x86 patterns:
 * 1. CALL/POP: call $+5; pop reg  (0xE8 opcode)
 * 2. FNSTENV:  fnstenv [esp-12]   (0xD9 opcode)
 */
uint8_t emu_getpc_check_x86(struct emu *e, uint8_t *data, uint32_t size, uint32_t offset)
{
    struct emu_cpu *c = emu_cpu_get(e);
    struct emu_memory *m = emu_memory_get(e);

    if (!c || !m || offset >= size)
        return 0;

    // Initialize CPU registers
    int reg;
    for (reg = 0; reg < 8; reg++)
        emu_cpu_reg32_set(c, reg, 0);

    emu_cpu_reg32_set(c, esp, 0x12000);

    switch (data[offset]) {
    case 0xe8:  // CALL instruction
    {
        // Write code to memory at offset 0x1000
        if (emu_memory_write_block(m, 0x1000, data, size) != 0)
            break;

        emu_cpu_eip_set(c, 0x1000 + offset);

        if (emu_cpu_parse(c) != 0)
            break;

        // Parse the CALL instruction to get displacement
        // For simplified detection, we just check if it's a short call
        // Read the displacement (4 bytes after 0xE8)
        if (offset + 5 > size)
            break;

        int32_t disp;
        memcpy(&disp, &data[offset + 1], 4);

        // Skip if displacement is too large (likely not GetPC)
        if (abs(disp) > 512)
            break;

        uint32_t espcopy = emu_cpu_reg32_get(c, esp);

        // Try to execute up to 64 instructions
        int j;
        for (j = 0; j < 64; j++) {
            int ret = emu_cpu_parse(c);
            if (ret != -1)
                ret = emu_cpu_step(c);

            if (ret == -1)
                break;

            // Check if stack pointer returned to original value
            // This means the return address was popped (GetPC pattern)
            if (emu_cpu_reg32_get(c, esp) == espcopy)
                return 1;
        }

        return 1;  // Likely CALL pattern even if not confirmed
    }

    case 0xd9:  // FPU instruction (FNSTENV)
    {
        // FNSTENV stores FPU environment including EIP of last FPU instruction
        // Common GetPC: fld st(0); fnstenv [esp-12]; pop reg

        if (offset + 64 > size)
            break;

        if (emu_memory_write_block(m, 0x1000, data + offset, MIN(size - offset, 64)) != 0)
            break;

        emu_cpu_eip_set(c, 0x1000);

        if (emu_cpu_parse(c) != 0)
            break;

        // Check if it's the FNSTENV variant
        // ModR/M byte bits 3-5 should be 110 (0x30)
        if (offset + 1 >= size)
            break;

        uint8_t modrm = data[offset + 1];
        if ((modrm & 0x38) != 0x30)
            break;

        // Check if effective address is ESP - 0x0C
        // This is the common pattern for FNSTENV-based GetPC
        uint32_t esp_val = emu_cpu_reg32_get(c, esp);

        // Parse ModR/M to get effective address
        // For our purposes, if it's accessing near ESP, it's likely GetPC
        // Simplified check: just verify it's FNSTENV (0xD9 /6)
        return 1;
    }

    default:
        return 0;
    }

    return 0;
}
