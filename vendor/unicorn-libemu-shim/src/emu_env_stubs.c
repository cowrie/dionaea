// ABOUTME: Stub implementations for Phase 3 environment emulation features
// ABOUTME: Provides minimal non-functional stubs until full implementation

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <emu/emu.h>
#include <emu/emu_cpu.h>
#include <emu/emu_memory.h>
#include <emu/emu_log.h>
#include <emu/emu_string.h>
#include <emu/environment/emu_env.h>
#include <emu/environment/emu_profile.h>
#include <emu/environment/win32/emu_env_w32.h>
#include <emu/environment/win32/emu_env_w32_dll.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>
#include <emu/environment/linux/emu_env_linux.h>

//
// CPU stubs (functions already in emu_wrapper.c are not duplicated here)
//

void emu_cpu_debugflag_set(struct emu_cpu *cpu, uint32_t flags) {
    // Stub: debug flags not implemented in Phase 1
}

void emu_cpu_debugflag_unset(struct emu_cpu *cpu, uint32_t flags) {
    // Stub: debug flags not implemented in Phase 1
}

//
// Environment stubs
//

struct emu_env *emu_env_new(struct emu *e) {
    struct emu_env *env = calloc(1, sizeof(struct emu_env));
    if (!env) return NULL;

    env->emu = e;
    env->userdata = NULL;
    env->profile = NULL;
    env->env.win = NULL;  // Windows/Linux environment not initialized

    fprintf(stderr, "WARNING: emu_env_new() - full environment emulation not implemented in Phase 1\n");
    return env;
}

void emu_env_free(struct emu_env *env) {
    if (!env) return;

    if (env->profile) {
        emu_profile_free(env->profile);
    }

    // Note: env->env.win/linux would need cleanup if implemented
    free(env);
}

//
// Profile stubs
//

struct emu_profile *emu_profile_new(void) {
    struct emu_profile *profile = calloc(1, sizeof(struct emu_profile));
    if (!profile) return NULL;

    profile->functions = NULL;  // Empty list
    return profile;
}

void emu_profile_free(struct emu_profile *profile) {
    if (!profile) return;
    // Would need to free function list and all arguments
    free(profile);
}

//
// Windows environment stubs
//

int32_t emu_env_w32_load_dll(struct emu_env_w32 *env, const char *dllname) {
    fprintf(stderr, "WARNING: emu_env_w32_load_dll(%s) - not implemented in Phase 1\n", dllname);
    return -1;
}

int32_t emu_env_w32_export_hook(struct emu_env *env, const char *exportname,
                                 uint32_t (*userhook)(struct emu_env *env, struct emu_env_hook *hook, ...),
                                 void *userdata) {
    // Stub: Windows API hooking not implemented in Phase 1
    return -1;
}

struct emu_env_hook *emu_env_w32_eip_check(struct emu_env *env) {
    // Stub: Windows API hooking not implemented in Phase 1
    return NULL;
}

//
// Linux environment stubs
//

int32_t emu_env_linux_syscall_hook(struct emu_env *env, const char *syscallname,
                                    uint32_t (*userhook)(struct emu_env *env, struct emu_env_hook *hook, ...),
                                    void *userdata) {
    // Stub: Linux syscall hooking not implemented in Phase 1
    return -1;
}

struct emu_env_hook *emu_env_linux_syscall_check(struct emu_env *env) {
    // Stub: Linux syscall hooking not implemented in Phase 1
    return NULL;
}

//
// Hashtable stubs
//

struct emu_hashtable_item *emu_hashtable_search(void *table, void *key) {
    // Stub: hashtable not implemented in Phase 1
    return NULL;
}
