// ABOUTME: Stub header for libemu logging API
// ABOUTME: Minimal definitions for Phase 1 compatibility

#ifndef EMU_LOG_H
#define EMU_LOG_H

struct emu;
struct emu_logging;

// Log levels
enum emu_log_level {
    EMU_LOG_NONE = 0,
    EMU_LOG_DEBUG = 1,
    EMU_LOG_INFO = 2,
    EMU_LOG_WARNING = 3,
    EMU_LOG_ERROR = 4
};

// Get logging interface
struct emu_logging *emu_logging_get(struct emu *e);

// Set log level (signature must match emu.h)
void emu_log_level_set(struct emu_logging *log, int level);

#endif // EMU_LOG_H
