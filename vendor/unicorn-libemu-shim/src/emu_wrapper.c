// ABOUTME: Core emulator wrapper implementation
// ABOUTME: Wraps Unicorn engine to provide libemu-compatible API for dionaea

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unicorn/unicorn.h>

#include "emu/emu.h"

#define CODE_OFFSET 0x00417000  // Default code offset (matches libemu)
#define STACK_BASE  0x00120000  // Default stack base

// Create new emulator instance
struct emu *emu_new(void)
{
    struct emu *e = calloc(1, sizeof(struct emu));
    if (!e)
        return NULL;

    // Initialize Unicorn engine (x86 32-bit mode)
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &e->uc);
    if (err != UC_ERR_OK) {
        free(e);
        return NULL;
    }

    // Allocate CPU wrapper
    e->cpu = calloc(1, sizeof(struct emu_cpu));
    if (!e->cpu) {
        uc_close(e->uc);
        free(e);
        return NULL;
    }
    e->cpu->uc = e->uc;
    e->cpu->emu = e;

    // Allocate memory wrapper
    e->mem = calloc(1, sizeof(struct emu_memory));
    if (!e->mem) {
        free(e->cpu);
        uc_close(e->uc);
        free(e);
        return NULL;
    }
    e->mem->uc = e->uc;
    e->mem->emu = e;

    // Allocate logging stub
    e->log = calloc(1, sizeof(struct emu_logging));
    if (!e->log) {
        free(e->mem);
        free(e->cpu);
        uc_close(e->uc);
        free(e);
        return NULL;
    }

    e->last_error = EMU_ERROR_NONE;

    return e;
}

// Free emulator instance
void emu_free(struct emu *e)
{
    if (!e)
        return;

    if (e->uc)
        uc_close(e->uc);

    free(e->log);
    free(e->mem);
    free(e->cpu);
    free(e);
}

// Get last error code
int emu_errno(struct emu *e)
{
    return e ? e->last_error : EMU_ERROR_NONE;
}

// Get error string
const char *emu_strerror(struct emu *e)
{
    if (!e)
        return "No emulator";

    switch (e->last_error) {
    case EMU_ERROR_NONE:
        return "No error";
    case EMU_ERROR_UNINITIALIZED:
        return "Uninitialized";
    case EMU_ERROR_MEMORY:
        return "Memory error";
    case EMU_ERROR_CPU:
        return "CPU error";
    default:
        return "Unknown error";
    }
}

// CPU functions
struct emu_cpu *emu_cpu_get(struct emu *e)
{
    return e ? e->cpu : NULL;
}

void emu_cpu_eip_set(struct emu_cpu *cpu, uint32_t eip)
{
    if (cpu && cpu->uc)
        uc_reg_write(cpu->uc, UC_X86_REG_EIP, &eip);
}

uint32_t emu_cpu_eip_get(struct emu_cpu *cpu)
{
    uint32_t eip = 0;
    if (cpu && cpu->uc)
        uc_reg_read(cpu->uc, UC_X86_REG_EIP, &eip);
    return eip;
}

// Map register enum to Unicorn register IDs
static int reg_to_uc_reg(int reg)
{
    static const int reg_map[] = {
        UC_X86_REG_EAX,  // eax = 0
        UC_X86_REG_ECX,  // ecx = 1
        UC_X86_REG_EDX,  // edx = 2
        UC_X86_REG_EBX,  // ebx = 3
        UC_X86_REG_ESP,  // esp = 4
        UC_X86_REG_EBP,  // ebp = 5
        UC_X86_REG_ESI,  // esi = 6
        UC_X86_REG_EDI   // edi = 7
    };

    if (reg >= 0 && reg < 8)
        return reg_map[reg];

    return -1;
}

void emu_cpu_reg32_set(struct emu_cpu *cpu, int reg, uint32_t value)
{
    if (!cpu || !cpu->uc)
        return;

    int uc_reg = reg_to_uc_reg(reg);
    if (uc_reg >= 0)
        uc_reg_write(cpu->uc, uc_reg, &value);
}

uint32_t emu_cpu_reg32_get(struct emu_cpu *cpu, int reg)
{
    uint32_t value = 0;

    if (!cpu || !cpu->uc)
        return 0;

    int uc_reg = reg_to_uc_reg(reg);
    if (uc_reg >= 0)
        uc_reg_read(cpu->uc, uc_reg, &value);

    return value;
}

void emu_cpu_eflags_set(struct emu_cpu *cpu, uint32_t flags)
{
    if (cpu && cpu->uc)
        uc_reg_write(cpu->uc, UC_X86_REG_EFLAGS, &flags);
}

uint32_t emu_cpu_eflags_get(struct emu_cpu *cpu)
{
    uint32_t flags = 0;
    if (cpu && cpu->uc)
        uc_reg_read(cpu->uc, UC_X86_REG_EFLAGS, &flags);
    return flags;
}

// CPU execution stubs (for GetPC detection)
int32_t emu_cpu_parse(struct emu_cpu *cpu)
{
    // Stub - Unicorn doesn't need separate parse step
    return 0;
}

int32_t emu_cpu_step(struct emu_cpu *cpu)
{
    if (!cpu || !cpu->uc)
        return -1;

    uint32_t eip = emu_cpu_eip_get(cpu);
    uc_err err = uc_emu_start(cpu->uc, eip, 0, 0, 1);  // Execute 1 instruction

    return (err == UC_ERR_OK) ? 0 : -1;
}

int32_t emu_cpu_run(struct emu_cpu *cpu, int steps)
{
    if (!cpu || !cpu->uc)
        return -1;

    uint32_t eip = emu_cpu_eip_get(cpu);
    uc_err err = uc_emu_start(cpu->uc, eip, 0, 0, steps);

    return (err == UC_ERR_OK) ? 0 : -1;
}

// Memory functions
struct emu_memory *emu_memory_get(struct emu *e)
{
    return e ? e->mem : NULL;
}

int32_t emu_memory_write_block(struct emu_memory *mem, uint32_t addr, void *data, uint32_t size)
{
    if (!mem || !mem->uc || !data)
        return -1;

    // Calculate page-aligned base address
    uint32_t base = addr & ~0xFFF;  // Align to 4KB page
    uint32_t offset = addr - base;
    uint32_t map_size = ((offset + size + 0xFFF) & ~0xFFF);  // Round up to page

    // Try to map memory (might already be mapped)
    uc_mem_map(mem->uc, base, map_size, UC_PROT_ALL);

    // Write the data
    uc_err err = uc_mem_write(mem->uc, addr, data, size);
    return (err == UC_ERR_OK) ? 0 : -1;
}

int32_t emu_memory_read_block(struct emu_memory *mem, uint32_t addr, void *dest, uint32_t size)
{
    if (!mem || !mem->uc || !dest)
        return -1;

    uc_err err = uc_mem_read(mem->uc, addr, dest, size);
    return (err == UC_ERR_OK) ? 0 : -1;
}

int32_t emu_memory_write_byte(struct emu_memory *mem, uint32_t addr, uint8_t byte)
{
    return emu_memory_write_block(mem, addr, &byte, 1);
}

int32_t emu_memory_read_byte(struct emu_memory *mem, uint32_t addr, uint8_t *byte)
{
    return emu_memory_read_block(mem, addr, byte, 1);
}

int32_t emu_memory_write_dword(struct emu_memory *mem, uint32_t addr, uint32_t value)
{
    return emu_memory_write_block(mem, addr, &value, 4);
}

int32_t emu_memory_read_dword(struct emu_memory *mem, uint32_t addr, uint32_t *value)
{
    return emu_memory_read_block(mem, addr, value, 4);
}

void emu_memory_clear(struct emu_memory *mem)
{
    // Stub - Unicorn doesn't have a clear operation
    // In practice, we recreate the emulator for each test
}

void emu_memory_mode_ro(struct emu_memory *mem)
{
    // Stub - not needed for our simplified detection
}

void emu_memory_mode_rw(struct emu_memory *mem)
{
    // Stub - not needed for our simplified detection
}

// Logging functions (stubs)
struct emu_logging *emu_logging_get(struct emu *e)
{
    return e ? e->log : NULL;
}

void emu_log_level_set(struct emu_logging *log, int level)
{
    if (log)
        log->level = level;
}
