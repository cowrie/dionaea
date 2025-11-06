// ABOUTME: Stub header for libemu environment emulation (Phase 3 feature)
// ABOUTME: Provides OS environment simulation for shellcode execution

#ifndef EMU_ENV_H
#define EMU_ENV_H

#include <stdint.h>

struct emu;
struct emu_profile;
struct emu_env_w32;
struct emu_env_linux;
struct emu_env_w32_dll_export;
struct emu_env_linux_syscall;

// Environment type enum
enum emu_env_type {
    emu_env_type_win32,
    emu_env_type_linux
};

// Environment hook structure (matches libemu)
struct emu_env_hook {
    enum emu_env_type type;
    union {
        struct emu_env_w32_dll_export *win;
        struct emu_env_linux_syscall *lin;
    } hook;
};

// Main environment structure
struct emu_env {
    struct emu *emu;
    void *userdata;
    struct emu_profile *profile;

    union {
        struct emu_env_w32 *win;
        struct emu_env_linux *lin;  // Note: 'linux' is a system macro, use 'lin'
    } env;
};

// Environment management
struct emu_env *emu_env_new(struct emu *e);
void emu_env_free(struct emu_env *env);

#endif // EMU_ENV_H
