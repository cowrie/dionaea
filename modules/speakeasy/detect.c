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
	g_debug("%s", __PRETTY_FUNCTION__);

	struct speakeasy_ctx *ctx = g_malloc0(sizeof(struct speakeasy_ctx));
	ctx->offset = 0;

	return ctx;
}

/**
 * Free per-connection context
 */
void proc_speakeasy_ctx_free(void *ctx)
{
	g_debug("%s", __PRETTY_FUNCTION__);
	g_free(ctx);
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

	// Detect shellcode using libemu's GetPC pattern detection
	struct emu *e = emu_new();
	int ret = emu_shellcode_test_x86(e, streamdata, size);
	emu_free(e);

	g_debug("emu_shellcode_test_x86 returned: %d", ret);

	// Update offset to avoid re-scanning
	ctx->offset += size;

	if (ret >= 0) {
		// Shellcode detected at offset ret
		g_info("Shellcode detected at offset %d (stream size: %d)", ret, size);

		// Create incident with shellcode data for Python Speakeasy handler
		struct incident *ix = incident_new("dionaea.shellcode.detected");

		// Attach raw shellcode data (from detected offset to end) as bytes
		GString *shellcode_bytes = g_string_new_len(streamdata + ret, size - ret);
		incident_value_bytes_set(ix, "data", shellcode_bytes);

		// Attach detection offset
		incident_value_int_set(ix, "offset", ret);

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
