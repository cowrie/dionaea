// ABOUTME: Shellcode detection API for dionaea
// ABOUTME: Detects x86 shellcode using GetPC patterns and execution heuristics

#ifndef EMU_SHELLCODE_H
#define EMU_SHELLCODE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct emu;

/**
 * Tests a buffer for x86 (32-bit) shellcode
 *
 * Scans for GetPC patterns (CALL/POP, FNSTENV) and attempts execution
 * from detected offsets. Returns offset if code executes > threshold instructions.
 *
 * @param e     The emulator instance
 * @param data  Buffer to test
 * @param size  Size of buffer
 *
 * @return Offset of detected shellcode, or -1 if no shellcode found
 */
int32_t emu_shellcode_test_x86(struct emu *e, uint8_t *data, uint16_t size);

/**
 * Check if offset contains an x86 GetPC pattern
 *
 * @param e      The emulator instance
 * @param data   Buffer containing code
 * @param size   Size of buffer
 * @param offset Offset to check
 *
 * @return 1 if GetPC detected, 0 otherwise
 */
uint8_t emu_getpc_check_x86(struct emu *e, uint8_t *data, uint32_t size, uint32_t offset);

#ifdef __cplusplus
}
#endif

#endif // EMU_SHELLCODE_H
