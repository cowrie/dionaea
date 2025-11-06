// ABOUTME: Header for libemu GetPC detection (already implemented)
// ABOUTME: Provides shellcode position-independent code pattern detection

#ifndef EMU_GETPC_H
#define EMU_GETPC_H

#include <stdint.h>

struct emu;

// GetPC detection (implemented in emu_getpc.c)
uint8_t emu_getpc_check(struct emu *e, uint8_t *data, uint32_t size, uint32_t offset);

#endif // EMU_GETPC_H
