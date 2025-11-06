// ABOUTME: Stub header for libemu Windows environment emulation (Phase 3 feature)
// ABOUTME: Simulates Windows API for shellcode execution

#ifndef EMU_ENV_W32_H
#define EMU_ENV_W32_H

#include <stdint.h>

// Forward declare socket types (no winsock2.h on Linux)
#ifndef _WIN32
struct sockaddr;
typedef int SOCKET;
#define INVALID_SOCKET -1
#endif

struct emu_env;
struct emu_env_hook;
struct emu_hashtable;
struct emu_env_w32_dll;

// Windows-specific structures
typedef struct {
    uint32_t hStdInput;
    uint32_t hStdOutput;
    uint32_t hStdError;
    // ... other STARTUPINFO fields
} STARTUPINFO;

typedef struct {
    uint32_t hProcess;
    uint32_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} PROCESS_INFORMATION;

// Windows environment structure
struct emu_env_w32 {
    struct emu_hashtable *exports;
    struct emu_env_w32_dll **loaded_dlls;
};

// DLL loading
int32_t emu_env_w32_load_dll(struct emu_env_w32 *env, const char *dllname);

// Hook functions
int32_t emu_env_w32_export_hook(struct emu_env *env, const char *exportname,
                                 uint32_t (*userhook)(struct emu_env *env, struct emu_env_hook *hook, ...),
                                 void *userdata);
struct emu_env_hook *emu_env_w32_eip_check(struct emu_env *env);

#endif // EMU_ENV_W32_H
