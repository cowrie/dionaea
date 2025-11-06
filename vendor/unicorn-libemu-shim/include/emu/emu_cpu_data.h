// ABOUTME: Stub header for libemu CPU data structures
// ABOUTME: Minimal definitions for Phase 1 compatibility

#ifndef EMU_CPU_DATA_H
#define EMU_CPU_DATA_H

#include <stdint.h>

// Stack manipulation macros (used by hooks.c)
#define POP_DWORD(cpu, val) \
    do { \
        uint32_t esp_val = emu_cpu_reg32_get(cpu, esp); \
        *(val) = 0; \
        emu_memory_read_dword(emu_memory_get(((struct emu_cpu_internal*)cpu)->emu), esp_val, (val)); \
        emu_cpu_reg32_set(cpu, esp, esp_val + 4); \
    } while(0)

// Forward declarations
struct emu_memory;
struct emu_memory *emu_memory_get(struct emu *e);
int32_t emu_memory_read_dword(struct emu_memory *mem, uint32_t addr, uint32_t *data);

// Internal CPU structure (opaque)
struct emu_cpu_internal {
    struct emu *emu;
};

#endif // EMU_CPU_DATA_H
