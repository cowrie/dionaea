// ABOUTME: Stub header for libemu profiling API (Phase 3 feature)
// ABOUTME: Tracks API calls made by shellcode during emulation

#ifndef EMU_PROFILE_H
#define EMU_PROFILE_H

#include <stdint.h>
#include <stdbool.h>

struct emu_profile;
struct emu_profile_function;
struct emu_profile_argument;
struct emu_list_root;

// Rendering types for arguments
enum render_type {
    render_none,
    render_int,
    render_short,
    render_string,
    render_bytea,
    render_ptr,
    render_ip,
    render_port,
    render_array,
    render_struct
};

// Profile argument structure
struct emu_profile_argument {
    char *argname;
    enum render_type render;
    union {
        int32_t tint;
        int16_t tshort;
        char *tchar;
        struct {
            unsigned char *data;
            unsigned int size;
        } bytea;
        struct {
            uint32_t addr;
            struct emu_profile_argument *ptr;
        } tptr;
        struct {
            struct emu_list_root *arguments;
        } tstruct;
    } value;
};

// Profile function structure
struct emu_profile_function {
    char *fnname;
    struct emu_list_root *arguments;
    struct emu_profile_argument *return_value;
};

// Profile structure
struct emu_profile {
    struct emu_list_root *functions;
};

// Profile management (stubs for now)
struct emu_profile *emu_profile_new(void);
void emu_profile_free(struct emu_profile *profile);

// List navigation macros (stub implementations)
#define emu_profile_functions_first(root) ((struct emu_profile_function*)root)
#define emu_profile_functions_istail(func) (func == NULL)
#define emu_profile_functions_next(func) ((struct emu_profile_function*)NULL)

#define emu_profile_arguments_first(root) ((struct emu_profile_argument*)root)
#define emu_profile_arguments_istail(arg) (arg == NULL)
#define emu_profile_arguments_next(arg) ((struct emu_profile_argument*)NULL)

#endif // EMU_PROFILE_H
