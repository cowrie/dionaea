// ABOUTME: Core emulator structures and functions for dionaea compatibility
// ABOUTME: Wraps Unicorn engine to provide libemu-compatible API

#ifndef EMU_H
#define EMU_H

#include <stdint.h>
#include <stdbool.h>
#include <unicorn/unicorn.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
struct emu;
struct emu_cpu;
struct emu_memory;
struct emu_env;
struct emu_logging;

// Error codes
#define EMU_ERROR_NONE 0
#define EMU_ERROR_UNINITIALIZED -1
#define EMU_ERROR_MEMORY -2
#define EMU_ERROR_CPU -3

// Main emulator structure
struct emu {
    uc_engine *uc;              // Unicorn engine instance
    struct emu_cpu *cpu;        // CPU wrapper
    struct emu_memory *mem;     // Memory wrapper
    struct emu_logging *log;    // Logging (stub for now)
    int last_error;             // Last error code
};

// CPU structure (wraps Unicorn)
struct emu_cpu {
    uc_engine *uc;              // Reference to Unicorn engine
    struct emu *emu;            // Back reference to emulator
    char instr_string[256];     // Last instruction (for debugging)
};

// Memory structure (wraps Unicorn)
struct emu_memory {
    uc_engine *uc;              // Reference to Unicorn engine
    struct emu *emu;            // Back reference to emulator
};

// Logging structure (minimal stub)
struct emu_logging {
    int level;
};

// Core emulator functions
struct emu *emu_new(void);
void emu_free(struct emu *e);
int emu_errno(struct emu *e);
const char *emu_strerror(struct emu *e);

// CPU functions
struct emu_cpu *emu_cpu_get(struct emu *e);
void emu_cpu_eip_set(struct emu_cpu *cpu, uint32_t eip);
uint32_t emu_cpu_eip_get(struct emu_cpu *cpu);
void emu_cpu_reg32_set(struct emu_cpu *cpu, int reg, uint32_t value);
uint32_t emu_cpu_reg32_get(struct emu_cpu *cpu, int reg);
void emu_cpu_eflags_set(struct emu_cpu *cpu, uint32_t flags);
uint32_t emu_cpu_eflags_get(struct emu_cpu *cpu);

// CPU execution
int32_t emu_cpu_parse(struct emu_cpu *cpu);
int32_t emu_cpu_step(struct emu_cpu *cpu);
int32_t emu_cpu_run(struct emu_cpu *cpu, int steps);

// Memory functions
struct emu_memory *emu_memory_get(struct emu *e);
int32_t emu_memory_write_block(struct emu_memory *mem, uint32_t addr, void *data, uint32_t size);
int32_t emu_memory_read_block(struct emu_memory *mem, uint32_t addr, void *dest, uint32_t size);
int32_t emu_memory_write_byte(struct emu_memory *mem, uint32_t addr, uint8_t byte);
int32_t emu_memory_read_byte(struct emu_memory *mem, uint32_t addr, uint8_t *byte);
int32_t emu_memory_write_dword(struct emu_memory *mem, uint32_t addr, uint32_t value);
int32_t emu_memory_read_dword(struct emu_memory *mem, uint32_t addr, uint32_t *value);

// Memory management
void emu_memory_clear(struct emu_memory *mem);
void emu_memory_mode_ro(struct emu_memory *mem);  // Read-only mode
void emu_memory_mode_rw(struct emu_memory *mem);  // Read-write mode

// Logging functions (stubs)
struct emu_logging *emu_logging_get(struct emu *e);
void emu_log_level_set(struct emu_logging *log, int level);

// CPU register enumeration
enum emu_reg {
    eax = 0,
    ecx = 1,
    edx = 2,
    ebx = 3,
    esp = 4,
    ebp = 5,
    esi = 6,
    edi = 7
};

#ifdef __cplusplus
}
#endif

#endif // EMU_H
