// ABOUTME: Stub header for Windows DLL export emulation (Phase 3 feature)
// ABOUTME: Defines structures for exported API functions

#ifndef EMU_ENV_W32_DLL_EXPORT_H
#define EMU_ENV_W32_DLL_EXPORT_H

#include <stdint.h>

struct emu_env;
struct emu_env_hook;

// DLL export structure (matches libemu)
struct emu_env_w32_dll_export {
    char *fnname;
    uint32_t virtualaddr;
    int32_t (*fnhook)(struct emu_env *env, struct emu_env_hook *hook);      // Low-level hooks
    void *userdata;
    uint32_t (*userhook)(struct emu_env *env, struct emu_env_hook *hook, ...); // User hooks
    uint32_t ordinal;
};

struct emu_hashtable_item {
    void *key;
    void *value;
};

// Hashtable operations
struct emu_hashtable_item *emu_hashtable_search(void *table, void *key);

#endif // EMU_ENV_W32_DLL_EXPORT_H
