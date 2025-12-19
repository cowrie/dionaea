// ABOUTME: x86 shellcode detection using GetPC pattern matching
// ABOUTME: Emits incidents with raw shellcode data for Python Speakeasy handler

/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 * SPDX-FileCopyrightText: 2024 Michel Oosterhof
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ev.h>
#include <glib.h>

#include <emu/emu.h>
#include <emu/emu_shellcode.h>

#include "dionaea.h"
#include "processor.h"
#include "connection.h"
#include "log.h"
#include "incident.h"
#include "threads.h"

#define D_LOG_DOMAIN "speakeasy"

#include "module.h"

/**
 * Processor definition
 * Uses threaded I/O because shellcode detection is CPU-intensive
 */
struct processor proc_speakeasy = {
	.name = "speakeasy",
	.new = proc_speakeasy_ctx_new,
	.free = proc_speakeasy_ctx_free,
	.cfg = proc_speakeasy_ctx_cfg_new,
	.thread_io_in = proc_speakeasy_on_io_in,
};

/**
 * Load processor configuration from dionaea.cfg
 * Minimal config - just validates the section exists
 */
void *proc_speakeasy_ctx_cfg_new(gchar *group_name)
{
	g_debug("%s: loading config for %s", __PRETTY_FUNCTION__, group_name);

	// No configuration needed for detection - just return non-NULL
	// to indicate config was loaded successfully
	return (void *)1;
}

/**
 * Create per-connection context
 * Tracks offset to avoid re-scanning already processed data
 */
void *proc_speakeasy_ctx_new(void *cfg)
{
	struct speakeasy_ctx *ctx = g_malloc0(sizeof(struct speakeasy_ctx));
	ctx->offset = 0;

	return ctx;
}

/**
 * Free per-connection context
 */
void proc_speakeasy_ctx_free(void *ctx)
{
	g_free(ctx);
}

/**
 * Detect x86-64 shellcode using GetPC pattern matching
 *
 * Scans for common x86-64 GetPC sequences:
 * - call $+5; pop rax/rbx/rcx/rdx/rsi/rdi
 *
 * Returns offset of shellcode start, or -1 if not found
 */
static int detect_shellcode_x64(void *data, int size)
{
	unsigned char *bytes = (unsigned char *)data;

	// Common x86-64 GetPC patterns: E8 00 00 00 00 <pop reg>
	// call $+5 is always E8 00 00 00 00
	// Followed by pop into 64-bit register:
	// 58 = pop rax, 5B = pop rbx, 59 = pop rcx, 5A = pop rdx
	// 5E = pop rsi, 5F = pop rdi, 5D = pop rbp, 5C = pop rsp (rare)

	// Minimum shellcode size: pattern (6 bytes) + some code (20+ bytes)
	if (size < 26) {
		return -1;
	}

	for (int i = 0; i <= size - 26; i++) {
		// Check for: call $+5 (E8 00 00 00 00)
		if (bytes[i] == 0xE8 &&
		    bytes[i+1] == 0x00 &&
		    bytes[i+2] == 0x00 &&
		    bytes[i+3] == 0x00 &&
		    bytes[i+4] == 0x00) {

			// Check for pop into common 64-bit register
			unsigned char pop_reg = bytes[i+5];
			if (pop_reg >= 0x58 && pop_reg <= 0x5F) {
				// Reduce false positives: check that following bytes aren't all zeros
				// Real shellcode will have instructions after GetPC
				int zero_count = 0;
				for (int j = i + 6; j < i + 26 && j < size; j++) {
					if (bytes[j] == 0x00) zero_count++;
				}

				// If more than 80% zeros after GetPC, probably not shellcode
				if (zero_count > 16) {
					continue;
				}

				g_info("Found x86-64 GetPC pattern at offset %d (call+pop)", i);
				return i;
			}
		}
	}

	return -1;
}

/**
 * Process incoming data for shellcode detection
 *
 * This function:
 * 1. Retrieves buffered stream data (with 300-byte lookback)
 * 2. Scans for shellcode using GetPC pattern matching
 * 3. If shellcode found, emits incident with raw data for Python handler
 * 4. Marks processor as done (one shellcode per connection)
 *
 * Runs in thread pool because detection can be CPU-intensive
 */
void proc_speakeasy_on_io_in(struct connection *con, struct processor_data *pd)
{
	g_debug("%s con %p pd %p", __PRETTY_FUNCTION__, con, pd);

	struct speakeasy_ctx *ctx = pd->ctx;

	// Get stream data with 300-byte lookback to catch shellcode
	// that might span across multiple receives
	int offset = MAX(ctx->offset - 300, 0);
	void *streamdata = NULL;
	int32_t size = bistream_get_stream(pd->bistream, bistream_in, offset, -1, &streamdata);

	if (size == -1) {
		g_debug("No data available in stream");
		return;
	}

	g_debug("Got %d bytes from stream (offset: %d)", size, offset);

	// Log first and bytes around offset 92 for debugging
	if (size > 0) {
		unsigned char *data = (unsigned char *)streamdata;
		char hexbuf[128];
		int hexlen = 0;
		for (int i = 0; i < (size < 16 ? size : 16) && hexlen < 120; i++) {
			hexlen += snprintf(hexbuf + hexlen, sizeof(hexbuf) - hexlen, "%02x ", data[i]);
		}
		g_debug("First bytes: %s", hexbuf);

		// Also log bytes around offset 92 (where HTTP body likely starts)
		if (size > 92) {
			hexlen = 0;
			for (int i = 92; i < (size < 108 ? size : 108) && hexlen < 120; i++) {
				hexlen += snprintf(hexbuf + hexlen, sizeof(hexbuf) - hexlen, "%02x ", data[i]);
			}
			g_debug("Bytes at offset 92: %s", hexbuf);
		}
	}

	// Try detecting shellcode for both architectures
	// Check x86-32 first (most common), then x86-64
	struct emu *e = emu_new();
	int ret_x86 = emu_shellcode_test_x86(e, streamdata, size);
	emu_free(e);

	int ret_x64 = detect_shellcode_x64(streamdata, size);

	g_debug("Detection results: x86=%d x64=%d", ret_x86, ret_x64);

	// Update offset to end of scanned data (accounting for lookback)
	ctx->offset = offset + size;

	// Determine which architecture was detected (prefer earliest offset)
	int ret = -1;
	const char *arch = NULL;

	if (ret_x86 >= 0 && (ret_x64 < 0 || ret_x86 <= ret_x64)) {
		ret = ret_x86;
		arch = "x86";
	} else if (ret_x64 >= 0) {
		ret = ret_x64;
		arch = "x86_64";
	}

	if (ret >= 0) {
		// Shellcode detected at offset ret
		g_info("Shellcode detected at offset %d (arch: %s, stream size: %d)",
		       ret, arch, size);

		// Create incident with shellcode data for Python Speakeasy handler
		struct incident *ix = incident_new("dionaea.shellcode.detected");

		// Attach shellcode data starting from GetPC position
		// Note: Encoded shellcode with decoder stubs before GetPC may not emulate properly
		GString *shellcode_bytes = g_string_new_len(streamdata + ret, size - ret);
		incident_value_bytes_set(ix, "data", shellcode_bytes);

		// Offset is always 0 (execution starts at beginning of data)
		incident_value_int_set(ix, "offset", 0);

		// Attach architecture for Python handler
		incident_value_string_set(ix, "arch", g_string_new(arch));

		// Attach connection for context and increase refcount for async processing
		incident_value_con_set(ix, "con", con);
		connection_ref(con);

		// Queue incident for async reporting
		GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
		g_async_queue_push(aq, async_cmd_new(async_incident_report, ix));
		g_async_queue_unref(aq);
		ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);

		// Mark processor as done - we only detect one shellcode per connection
		pd->state = processor_done;
	}

	g_free(streamdata);
}
