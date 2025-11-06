// ABOUTME: Stub header for Windows DLL emulation (Phase 3 feature)
// ABOUTME: Manages Windows DLL exports for API hooking

#ifndef EMU_ENV_W32_DLL_H
#define EMU_ENV_W32_DLL_H

struct emu_hashtable;

// DLL structure
struct emu_env_w32_dll {
    char *dllname;
    struct emu_hashtable *exports_by_fnname;
    struct emu_hashtable *exports_by_fnptr;
};

#endif // EMU_ENV_W32_DLL_H
