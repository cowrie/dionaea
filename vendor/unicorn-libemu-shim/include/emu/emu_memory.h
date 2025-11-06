// ABOUTME: Stub header for libemu memory API
// ABOUTME: Provides memory interface already implemented in emu_wrapper.c

#ifndef EMU_MEMORY_H
#define EMU_MEMORY_H

#include <stdint.h>

struct emu;
struct emu_memory;

// Get memory interface from emulator
struct emu_memory *emu_memory_get(struct emu *e);

// Memory operations (already implemented in emu_wrapper.c)
int32_t emu_memory_read_byte(struct emu_memory *mem, uint32_t addr, uint8_t *data);
int32_t emu_memory_read_word(struct emu_memory *mem, uint32_t addr, uint16_t *data);
int32_t emu_memory_read_dword(struct emu_memory *mem, uint32_t addr, uint32_t *data);
int32_t emu_memory_read_block(struct emu_memory *mem, uint32_t addr, void *data, uint32_t size);

int32_t emu_memory_write_byte(struct emu_memory *mem, uint32_t addr, uint8_t data);
int32_t emu_memory_write_word(struct emu_memory *mem, uint32_t addr, uint16_t data);
int32_t emu_memory_write_dword(struct emu_memory *mem, uint32_t addr, uint32_t data);
int32_t emu_memory_write_block(struct emu_memory *mem, uint32_t addr, void *data, uint32_t size);

#endif // EMU_MEMORY_H
