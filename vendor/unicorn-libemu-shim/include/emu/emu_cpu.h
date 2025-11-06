// ABOUTME: Stub header for libemu CPU emulation API
// ABOUTME: Provides minimal interface for Phase 1; full implementation in Phase 3

#ifndef EMU_CPU_H
#define EMU_CPU_H

#include <stdint.h>

struct emu;
struct emu_cpu;

// CPU register constants and debug flags are defined in emu.h

// CPU debug flags (stub)
enum cpu_debugflag {
    instruction_string = 1
};

// Get CPU from emulator
struct emu_cpu *emu_cpu_get(struct emu *e);

// Register access
uint32_t emu_cpu_reg32_get(struct emu_cpu *cpu, int reg);
void emu_cpu_reg32_set(struct emu_cpu *cpu, int reg, uint32_t value);

// EIP access
uint32_t emu_cpu_eip_get(struct emu_cpu *cpu);
void emu_cpu_eip_set(struct emu_cpu *cpu, uint32_t eip);

// EFLAGS access
uint32_t emu_cpu_eflags_get(struct emu_cpu *cpu);
void emu_cpu_eflags_set(struct emu_cpu *cpu, uint32_t eflags);

// CPU execution (signatures must match emu.h)
int32_t emu_cpu_parse(struct emu_cpu *cpu);
int32_t emu_cpu_step(struct emu_cpu *cpu);
int32_t emu_cpu_run(struct emu_cpu *cpu, int steps);

// Debug flags (stub)
void emu_cpu_debugflag_set(struct emu_cpu *cpu, uint32_t flags);
void emu_cpu_debugflag_unset(struct emu_cpu *cpu, uint32_t flags);

#endif // EMU_CPU_H
