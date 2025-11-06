// ABOUTME: Stub header for Linux environment emulation (Phase 3 feature)
// ABOUTME: Simulates Linux syscalls for shellcode execution

#ifndef EMU_ENV_LINUX_H
#define EMU_ENV_LINUX_H

#include <stdint.h>

struct emu_env;
struct emu_env_hook;

// Linux syscall structure (stub for Phase 3)
struct emu_env_linux_syscall {
    char *name;
    int32_t (*fnhook)(struct emu_env *env, struct emu_env_hook *hook);
    void *userdata;
    uint32_t (*userhook)(struct emu_env *env, struct emu_env_hook *hook, ...);
};

// Syscall hooking
int32_t emu_env_linux_syscall_hook(struct emu_env *env, const char *syscallname,
                                    uint32_t (*userhook)(struct emu_env *env, struct emu_env_hook *hook, ...),
                                    void *userdata);

// Syscall checking
struct emu_env_hook *emu_env_linux_syscall_check(struct emu_env *env);

#endif // EMU_ENV_LINUX_H
