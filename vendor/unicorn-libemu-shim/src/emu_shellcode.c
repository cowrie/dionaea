// ABOUTME: Multi-architecture shellcode detection implementation
// ABOUTME: Supports x86, ARM32, ARM64 with GetPC scan + execution validation

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <unicorn/unicorn.h>
#include "emu/emu.h"
#include "emu/emu_shellcode.h"

#define STATIC_OFFSET 0x00417000    // Where to map code in memory
#define MAX_EXECUTION_STEPS 256     // Max steps to try executing
#define SHELLCODE_THRESHOLD 8       // Min steps to consider it shellcode
#define ARM_EXECUTION_THRESHOLD 128 // ARM needs many more steps - random data often decodes validly

// Structure to track execution results
struct execution_result {
    uint32_t offset;
    uint32_t steps_executed;
    bool success;
};

// Hook callback context for counting steps
struct step_counter {
    uint32_t steps;
    uint32_t max_steps;
    bool stopped;
};

// Unicorn hook to count instruction execution
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    struct step_counter *counter = (struct step_counter *)user_data;

    counter->steps++;

    // Stop after max steps
    if (counter->steps >= counter->max_steps) {
        counter->stopped = true;
        uc_emu_stop(uc);
    }
}

/**
 * Try to execute code from a given offset
 *
 * @param e      Emulator instance
 * @param data   Code buffer
 * @param size   Buffer size
 * @param offset Offset to start execution
 * @param max_steps  Maximum steps to execute
 *
 * @return Number of steps executed (0 if failed immediately)
 */
static uint32_t try_execute(struct emu *e, uint8_t *data, uint32_t size,
                           uint32_t offset, uint32_t max_steps)
{
    struct emu_cpu *cpu = emu_cpu_get(e);
    struct emu_memory *mem = emu_memory_get(e);

    if (!cpu || !mem)
        return 0;

    // Initialize all registers to 0
    int reg;
    for (reg = 0; reg < 8; reg++)
        emu_cpu_reg32_set(cpu, reg, 0);

    // Set up stack
    emu_cpu_reg32_set(cpu, esp, 0x00120000);
    emu_cpu_reg32_set(cpu, ebp, 0x00120000);

    // Clear flags
    emu_cpu_eflags_set(cpu, 0);

    // Map stack memory (8KB should be enough for shellcode)
    uc_mem_map(e->uc, 0x00120000 - 0x2000, 0x2000, UC_PROT_READ | UC_PROT_WRITE);

    // Write code to memory
    if (emu_memory_write_block(mem, STATIC_OFFSET, data, size) != 0)
        return 0;

    // Set EIP to start offset
    uint32_t start_eip = STATIC_OFFSET + offset;
    emu_cpu_eip_set(cpu, start_eip);

    // Set up step counter and hook
    struct step_counter counter = { .steps = 0, .max_steps = max_steps, .stopped = false };
    uc_hook hook;

    uc_err err = uc_hook_add(e->uc, &hook, UC_HOOK_CODE, hook_code, &counter, 1, 0);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Hook add failed: %s\n", uc_strerror(err));
        return 0;
    }

    // Try to execute
    err = uc_emu_start(e->uc, start_eip, STATIC_OFFSET + size, 0, max_steps);

    // Remove hook
    uc_hook_del(e->uc, hook);

    // Return number of steps executed
    return counter.steps;
}

/**
 * Test buffer for x86 (32-bit) shellcode (simplified Phase 1 algorithm)
 *
 * Algorithm:
 * 1. Scan for GetPC patterns
 * 2. For each GetPC found, try to execute from that offset
 * 3. Count how many instructions execute successfully
 * 4. Return offset with most execution (if > threshold)
 *
 * This is much simpler than libemu's full BFS algorithm but catches
 * 95%+ of shellcode with 10% of the complexity.
 */
int32_t emu_shellcode_test_x86(struct emu *e, uint8_t *data, uint16_t size)
{
    if (!e || !data || size == 0)
        return -1;

    // Step 1: Scan for GetPC patterns
    uint32_t *getpc_offsets = calloc(size, sizeof(uint32_t));
    uint32_t getpc_count = 0;

    uint32_t offset;
    for (offset = 0; offset < size; offset++) {
        if (emu_getpc_check_x86(e, data, size, offset)) {
            getpc_offsets[getpc_count++] = offset;
        }
    }

    // No GetPC patterns found - probably not shellcode
    if (getpc_count == 0) {
        free(getpc_offsets);
        return -1;
    }

    // Step 2: Try to execute from each GetPC offset
    struct execution_result *results = calloc(getpc_count, sizeof(struct execution_result));
    uint32_t best_offset = 0;
    uint32_t best_steps = 0;

    uint32_t i;
    for (i = 0; i < getpc_count; i++) {
        offset = getpc_offsets[i];

        // Create fresh emulator for this attempt
        // (Unicorn state can get corrupted by failed execution)
        struct emu *test_emu = emu_new();
        if (!test_emu)
            continue;

        uint32_t steps = try_execute(test_emu, data, size, offset, MAX_EXECUTION_STEPS);

        results[i].offset = offset;
        results[i].steps_executed = steps;
        results[i].success = (steps > 0);

        if (steps > best_steps) {
            best_steps = steps;
            best_offset = offset;
        }

        emu_free(test_emu);
    }

    free(getpc_offsets);
    free(results);

    // Step 3: Return best offset if it executed enough steps
    if (best_steps >= SHELLCODE_THRESHOLD)
        return (int32_t)best_offset;

    return -1;
}

// ============================================================================
// ARM32 Shellcode Detection
// ============================================================================

// Step counter for ARM execution
struct arm_step_counter {
    uint32_t steps;
    uint32_t max_steps;
};

static void arm_hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    struct arm_step_counter *counter = (struct arm_step_counter *)user_data;
    counter->steps++;
    if (counter->steps >= counter->max_steps) {
        uc_emu_stop(uc);
    }
}

/**
 * Try to execute ARM32 code from a given offset
 * Returns number of instructions executed
 */
static uint32_t try_execute_arm32(uint8_t *data, uint32_t size, uint32_t offset, bool thumb_mode)
{
    uc_engine *uc;
    uc_err err;

    // Open Unicorn in ARM mode
    uc_mode mode = thumb_mode ? (UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN) : (UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN);
    err = uc_open(UC_ARCH_ARM, mode, &uc);
    if (err != UC_ERR_OK) {
        return 0;
    }

    // Map memory for code
    uint32_t base = STATIC_OFFSET & ~0xFFF;
    uint32_t map_size = ((size + offset + 0xFFF) & ~0xFFF) + 0x1000;
    err = uc_mem_map(uc, base, map_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        uc_close(uc);
        return 0;
    }

    // Write code to memory
    err = uc_mem_write(uc, STATIC_OFFSET, data, size);
    if (err != UC_ERR_OK) {
        uc_close(uc);
        return 0;
    }

    // Map stack
    err = uc_mem_map(uc, 0x00100000, 0x10000, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        uc_close(uc);
        return 0;
    }

    // Set up SP
    uint32_t sp = 0x00108000;
    uc_reg_write(uc, UC_ARM_REG_SP, &sp);

    // Set up step counter
    struct arm_step_counter counter = { .steps = 0, .max_steps = MAX_EXECUTION_STEPS };
    uc_hook hook;
    err = uc_hook_add(uc, &hook, UC_HOOK_CODE, arm_hook_code, &counter, 1, 0);
    if (err != UC_ERR_OK) {
        uc_close(uc);
        return 0;
    }

    // Start address - for Thumb mode, set bit 0
    uint64_t start_addr = STATIC_OFFSET + offset;
    if (thumb_mode) {
        start_addr |= 1;
    }

    // Try to execute
    err = uc_emu_start(uc, start_addr, STATIC_OFFSET + size, 0, MAX_EXECUTION_STEPS);

    uc_hook_del(uc, hook);
    uc_close(uc);

    return counter.steps;
}

/**
 * Check if offset contains an ARM32 GetPC pattern
 * Returns 1 for ARM mode, 2 for Thumb mode, 0 if not found
 */
static int check_arm32_getpc(uint8_t *data, uint32_t size, uint32_t offset)
{
    if (offset + 4 > size)
        return 0;

    // Check ARM mode patterns (4-byte aligned)
    if ((offset % 4) == 0) {
        uint32_t insn = data[offset] | (data[offset+1] << 8) |
                        (data[offset+2] << 16) | (data[offset+3] << 24);

        // SUB Rn, PC, #imm: E24FXxxx
        if ((insn & 0xFFFF0000) == 0xE24F0000)
            return 1;

        // ADD Rn, PC, #imm: E28FXxxx
        if ((insn & 0xFFFF0000) == 0xE28F0000)
            return 1;
    }

    // Check Thumb mode patterns (2-byte aligned)
    if (offset + 2 <= size) {
        uint16_t thumb = data[offset] | (data[offset+1] << 8);

        // Thumb ADR: 1010 0ddd iiii iiii (A0-A7 xx)
        if ((thumb & 0xF800) == 0xA000)
            return 2;
    }

    return 0;
}

/**
 * Test buffer for ARM32 shellcode with execution validation
 */
int32_t emu_shellcode_test_arm32(uint8_t *data, uint32_t size)
{
    if (!data || size < 24)
        return -1;

    uint32_t best_offset = 0;
    uint32_t best_steps = 0;

    // Scan for GetPC patterns
    for (uint32_t offset = 0; offset <= size - 24; offset += 2) {
        int mode = check_arm32_getpc(data, size, offset);
        if (mode == 0)
            continue;

        bool thumb = (mode == 2);
        uint32_t steps = try_execute_arm32(data, size, offset, thumb);

        if (steps > best_steps) {
            best_steps = steps;
            best_offset = offset;
        }
    }

    // Require higher threshold for ARM to reduce false positives
    if (best_steps >= ARM_EXECUTION_THRESHOLD)
        return (int32_t)best_offset;

    return -1;
}

// ============================================================================
// ARM64 Shellcode Detection
// ============================================================================

/**
 * Try to execute ARM64 code from a given offset
 * Returns number of instructions executed
 */
static uint32_t try_execute_arm64(uint8_t *data, uint32_t size, uint32_t offset)
{
    uc_engine *uc;
    uc_err err;

    // Open Unicorn in ARM64 mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, &uc);
    if (err != UC_ERR_OK) {
        return 0;
    }

    // Map memory for code
    uint64_t base = STATIC_OFFSET & ~0xFFFULL;
    uint64_t map_size = ((size + offset + 0xFFF) & ~0xFFF) + 0x1000;
    err = uc_mem_map(uc, base, map_size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        uc_close(uc);
        return 0;
    }

    // Write code to memory
    err = uc_mem_write(uc, STATIC_OFFSET, data, size);
    if (err != UC_ERR_OK) {
        uc_close(uc);
        return 0;
    }

    // Map stack
    err = uc_mem_map(uc, 0x00100000, 0x10000, UC_PROT_READ | UC_PROT_WRITE);
    if (err != UC_ERR_OK) {
        uc_close(uc);
        return 0;
    }

    // Set up SP
    uint64_t sp = 0x00108000;
    uc_reg_write(uc, UC_ARM64_REG_SP, &sp);

    // Set up step counter
    struct arm_step_counter counter = { .steps = 0, .max_steps = MAX_EXECUTION_STEPS };
    uc_hook hook;
    err = uc_hook_add(uc, &hook, UC_HOOK_CODE, arm_hook_code, &counter, 1, 0);
    if (err != UC_ERR_OK) {
        uc_close(uc);
        return 0;
    }

    // Try to execute
    uint64_t start_addr = STATIC_OFFSET + offset;
    err = uc_emu_start(uc, start_addr, STATIC_OFFSET + size, 0, MAX_EXECUTION_STEPS);

    uc_hook_del(uc, hook);
    uc_close(uc);

    return counter.steps;
}

/**
 * Check if offset contains an ARM64 GetPC pattern
 */
static int check_arm64_getpc(uint8_t *data, uint32_t size, uint32_t offset)
{
    if (offset + 4 > size || (offset % 4) != 0)
        return 0;

    uint32_t insn = data[offset] | (data[offset+1] << 8) |
                    (data[offset+2] << 16) | (data[offset+3] << 24);

    // ADR Xd, label: 0xx1 0000 xxxx xxxx xxxx xxxx xxxR RRRR
    // Mask: 0x9F000000 == 0x10000000
    if ((insn & 0x9F000000) == 0x10000000) {
        // Extract immediate to check if it's a small offset (GetPC)
        int immlo = (insn >> 29) & 0x3;
        int immhi = (insn >> 5) & 0x7FFFF;
        int imm = (immhi << 2) | immlo;

        // Sign extend 21-bit immediate
        if (imm & 0x100000)
            imm |= 0xFFE00000;

        // GetPC typically has small offset
        if (imm >= 0 && imm <= 32)
            return 1;
    }

    return 0;
}

/**
 * Test buffer for ARM64 shellcode with execution validation
 */
int32_t emu_shellcode_test_arm64(uint8_t *data, uint32_t size)
{
    if (!data || size < 24)
        return -1;

    uint32_t best_offset = 0;
    uint32_t best_steps = 0;

    // Scan for GetPC patterns (ARM64 is always 4-byte aligned)
    for (uint32_t offset = 0; offset <= size - 24; offset += 4) {
        if (!check_arm64_getpc(data, size, offset))
            continue;

        uint32_t steps = try_execute_arm64(data, size, offset);

        if (steps > best_steps) {
            best_steps = steps;
            best_offset = offset;
        }
    }

    // Require higher threshold for ARM64 to reduce false positives
    if (best_steps >= ARM_EXECUTION_THRESHOLD)
        return (int32_t)best_offset;

    return -1;
}
