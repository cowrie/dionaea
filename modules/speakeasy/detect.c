// ABOUTME: Multi-architecture shellcode detection using GetPC pattern matching
// ABOUTME: Supports x86, x86-64, ARM32, ARM64, MIPS - saves and emits incidents

/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 * SPDX-FileCopyrightText: 2024 Michel Oosterhof
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

#include <ev.h>
#include <glib.h>
#include <openssl/evp.h>

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

// Directory to save shellcode files (set from config)
static char *shellcode_dir = NULL;

/**
 * Initialize shellcode storage directory from config
 * Called from module.c during module initialization
 */
void speakeasy_set_shellcode_dir(const char *dir)
{
	if (shellcode_dir != NULL) {
		g_free(shellcode_dir);
	}
	shellcode_dir = g_strdup(dir);
}

/**
 * Compute SHA256 hash of data and return as hex string
 * Caller must free the returned string with g_free()
 */
static char *compute_sha256_hex(const void *data, size_t len)
{
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_len;

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return NULL;
	}

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(ctx, data, len) != 1 ||
	    EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
		EVP_MD_CTX_free(ctx);
		return NULL;
	}
	EVP_MD_CTX_free(ctx);

	// Convert to hex string
	char *hex = g_malloc(hash_len * 2 + 1);
	for (unsigned int i = 0; i < hash_len; i++) {
		sprintf(hex + i * 2, "%02x", hash[i]);
	}
	hex[hash_len * 2] = '\0';

	return hex;
}

/**
 * Save shellcode to disk with metadata
 *
 * Saves:
 * - shellcode-<sha256>.bin: raw shellcode bytes
 * - shellcode-<sha256>.txt: metadata (arch, offset, connection info, timestamp)
 *
 * Returns true if saved successfully (or already exists), false on error
 */
static bool save_shellcode(const void *data, size_t len, int offset,
                           const char *arch, struct connection *con)
{
	if (shellcode_dir == NULL) {
		g_debug("shellcode_dir not configured, skipping save");
		return false;
	}

	char *sha256 = compute_sha256_hex(data, len);
	if (sha256 == NULL) {
		g_warning("Failed to compute SHA256");
		return false;
	}

	// Build file paths
	char *bin_path = g_strdup_printf("%s/shellcode-%s.bin", shellcode_dir, sha256);
	char *txt_path = g_strdup_printf("%s/shellcode-%s.txt", shellcode_dir, sha256);

	// Check if already exists (dedup by hash)
	struct stat st;
	if (stat(bin_path, &st) == 0) {
		g_debug("Shellcode %s already saved", sha256);
		g_free(sha256);
		g_free(bin_path);
		g_free(txt_path);
		return true;
	}

	// Save binary data
	FILE *f = fopen(bin_path, "wb");
	if (f == NULL) {
		g_warning("Failed to open %s for writing", bin_path);
		g_free(sha256);
		g_free(bin_path);
		g_free(txt_path);
		return false;
	}
	size_t written = fwrite(data, 1, len, f);
	fclose(f);

	if (written != len) {
		g_warning("Failed to write shellcode data");
		unlink(bin_path);
		g_free(sha256);
		g_free(bin_path);
		g_free(txt_path);
		return false;
	}

	// Save metadata
	f = fopen(txt_path, "w");
	if (f != NULL) {
		// Get timestamp
		time_t now = time(NULL);
		struct tm tm;
		gmtime_r(&now, &tm);
		char timebuf[32];
		strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", &tm);

		fprintf(f, "sha256: %s\n", sha256);
		fprintf(f, "arch: %s\n", arch);
		fprintf(f, "size: %zu\n", len);
		fprintf(f, "offset: %d\n", offset);
		if (con != NULL) {
			fprintf(f, "src: %s:%s\n",
			        con->remote.ip_string ? con->remote.ip_string : "?",
			        con->remote.port_string ? con->remote.port_string : "?");
			fprintf(f, "dst: %s:%s\n",
			        con->local.ip_string ? con->local.ip_string : "?",
			        con->local.port_string ? con->local.port_string : "?");
		}
		fprintf(f, "time: %s\n", timebuf);
		fclose(f);
	}

	g_info("Saved shellcode %s.bin (%zu bytes, %s)", sha256, len, arch);

	g_free(sha256);
	g_free(bin_path);
	g_free(txt_path);
	return true;
}

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
 * Check if bytes following a GetPC pattern look like real shellcode
 * Returns true if likely shellcode, false if likely false positive
 */
static int check_following_bytes(unsigned char *bytes, int start, int size)
{
	// Real shellcode will have instructions after GetPC
	// Count zeros in the next 20 bytes
	int zero_count = 0;
	int end = (start + 20 < size) ? start + 20 : size;
	for (int j = start; j < end; j++) {
		if (bytes[j] == 0x00) zero_count++;
	}

	// If more than 80% zeros, probably not shellcode
	return zero_count <= 16;
}

/**
 * Detect x86-64 shellcode using GetPC pattern matching
 *
 * Scans for common x86-64 GetPC sequences:
 * - call $+5; pop reg (E8 00 00 00 00 5x)
 * - call $+N; pop reg where N is small (for decoder stubs)
 * - FPU GetPC: fldz; fnstenv [esp-0xC]; pop reg
 * - jmp/call + pop combinations
 *
 * Returns offset of shellcode start, or -1 if not found
 */
static int detect_shellcode_x64(void *data, int size)
{
	unsigned char *bytes = (unsigned char *)data;

	// Minimum shellcode size: pattern (6 bytes) + some code (20+ bytes)
	if (size < 26) {
		return -1;
	}

	for (int i = 0; i <= size - 26; i++) {
		// Pattern 1: call $+5 (E8 00 00 00 00) followed by pop reg
		if (bytes[i] == 0xE8 &&
		    bytes[i+1] == 0x00 &&
		    bytes[i+2] == 0x00 &&
		    bytes[i+3] == 0x00 &&
		    bytes[i+4] == 0x00) {

			unsigned char pop_reg = bytes[i+5];
			// 58-5F = pop rax/rcx/rdx/rbx/rsp/rbp/rsi/rdi
			if (pop_reg >= 0x58 && pop_reg <= 0x5F) {
				if (check_following_bytes(bytes, i + 6, size)) {
					g_info("Found x86-64 GetPC at offset %d (call $+5; pop)", i);
					return i;
				}
			}
		}

		// Pattern 2: call with small positive displacement (decoder stub)
		// E8 xx 00 00 00 where xx <= 0x20 (32 bytes max displacement)
		if (bytes[i] == 0xE8 &&
		    bytes[i+1] <= 0x20 &&
		    bytes[i+2] == 0x00 &&
		    bytes[i+3] == 0x00 &&
		    bytes[i+4] == 0x00) {

			int disp = bytes[i+1];
			int pop_offset = i + 5 + disp;

			// Check if there's a pop after the call target
			if (pop_offset < size - 20) {
				unsigned char pop_reg = bytes[pop_offset];
				if (pop_reg >= 0x58 && pop_reg <= 0x5F) {
					if (check_following_bytes(bytes, pop_offset + 1, size)) {
						g_info("Found x86-64 GetPC at offset %d (call $+%d; pop)", i, disp + 5);
						return i;
					}
				}
			}
		}

		// Pattern 3: FPU GetPC - D9 EE D9 74 24 F4 5x
		// fldz (D9 EE); fnstenv [esp-0xC] (D9 74 24 F4); pop reg (5x)
		if (i <= size - 7 &&
		    bytes[i] == 0xD9 &&
		    bytes[i+1] == 0xEE &&
		    bytes[i+2] == 0xD9 &&
		    bytes[i+3] == 0x74 &&
		    bytes[i+4] == 0x24 &&
		    bytes[i+5] == 0xF4) {

			unsigned char pop_reg = bytes[i+6];
			if (pop_reg >= 0x58 && pop_reg <= 0x5F) {
				if (check_following_bytes(bytes, i + 7, size)) {
					g_info("Found x86-64 GetPC at offset %d (fpu fnstenv)", i);
					return i;
				}
			}
		}

		// Pattern 4: jmp short + call back pattern
		// EB xx E8 yy yy yy yy (jmp over call, call back, pop)
		if (i <= size - 10 &&
		    bytes[i] == 0xEB &&
		    bytes[i+1] >= 0x02 && bytes[i+1] <= 0x10) {

			int jmp_target = i + 2 + bytes[i+1];
			if (jmp_target < size - 6) {
				// Check for pop at jump target
				unsigned char pop_reg = bytes[jmp_target];
				if (pop_reg >= 0x58 && pop_reg <= 0x5F) {
					// Check for call before it
					if (bytes[i+2] == 0xE8) {
						if (check_following_bytes(bytes, jmp_target + 1, size)) {
							g_info("Found x86-64 GetPC at offset %d (jmp+call)", i);
							return i;
						}
					}
				}
			}
		}
	}

	return -1;
}

/**
 * Detect MIPS shellcode using GetPC pattern matching
 *
 * MIPS GetPC patterns (little-endian):
 * - BAL (Branch and Link to self or +4)
 * - BGEZAL $zero, label (always branches, stores PC+8 in $ra)
 * - BLTZAL $zero, label (never branches but still sets $ra on some MIPS)
 *
 * Returns offset of shellcode start, or -1 if not found
 */
static int detect_shellcode_mips(void *data, int size)
{
	unsigned char *bytes = (unsigned char *)data;

	// MIPS instructions are 4 bytes
	if (size < 24) {
		return -1;
	}

	// Check both little-endian and big-endian patterns
	for (int i = 0; i <= size - 24; i += 4) {
		// Little-endian MIPS
		uint32_t insn_le = bytes[i] | (bytes[i+1] << 8) |
		                   (bytes[i+2] << 16) | (bytes[i+3] << 24);

		// Big-endian MIPS
		uint32_t insn_be = (bytes[i] << 24) | (bytes[i+1] << 16) |
		                   (bytes[i+2] << 8) | bytes[i+3];

		// Pattern 1: BGEZAL $zero, offset (little-endian)
		// Encoding: 0000 01ss sss1 0001 iiii iiii iiii iiii
		// With rs=0: 0000 0100 0001 0001 = 0x04110000 + offset
		// Mask: 0xFFFF0000 == 0x04110000
		if ((insn_le & 0xFFFF0000) == 0x04110000) {
			int16_t offset = insn_le & 0xFFFF;
			// Small positive offset typical for GetPC
			if (offset >= 0 && offset <= 8) {
				if (check_following_bytes(bytes, i + 4, size)) {
					g_info("Found MIPS GetPC at offset %d (bgezal, LE)", i);
					return i;
				}
			}
		}

		// Same pattern, big-endian
		if ((insn_be & 0xFFFF0000) == 0x04110000) {
			int16_t offset = insn_be & 0xFFFF;
			if (offset >= 0 && offset <= 8) {
				if (check_following_bytes(bytes, i + 4, size)) {
					g_info("Found MIPS GetPC at offset %d (bgezal, BE)", i);
					return i;
				}
			}
		}

		// Pattern 2: BAL (Branch and Link)
		// BAL is actually BGEZAL with rs=0, same encoding
		// Some assemblers use: 0x04100001 for bal .+4

		// Pattern 3: BLTZAL $zero (sets $ra but doesn't branch)
		// Encoding: 0000 0100 0001 0000 = 0x04100000 + offset
		if ((insn_le & 0xFFFF0000) == 0x04100000) {
			int16_t offset = insn_le & 0xFFFF;
			if (offset >= 0 && offset <= 8) {
				if (check_following_bytes(bytes, i + 4, size)) {
					g_info("Found MIPS GetPC at offset %d (bltzal, LE)", i);
					return i;
				}
			}
		}

		if ((insn_be & 0xFFFF0000) == 0x04100000) {
			int16_t offset = insn_be & 0xFFFF;
			if (offset >= 0 && offset <= 8) {
				if (check_following_bytes(bytes, i + 4, size)) {
					g_info("Found MIPS GetPC at offset %d (bltzal, BE)", i);
					return i;
				}
			}
		}

		// Pattern 4: JAL with computed address (less common for GetPC)
		// JAL target: 0000 11ii iiii iiii iiii iiii iiii iiii
		// 0x0C000000 - not typically GetPC but can be part of shellcode
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

	// Try detecting shellcode for all supported architectures
	// All architectures now use execution-based validation to reduce false positives

	// x86-32 uses libemu for emulation-based detection
	struct emu *e = emu_new();
	int ret_x86 = emu_shellcode_test_x86(e, streamdata, size);
	emu_free(e);

	// x86-64 still uses pattern-based detection (TODO: add execution validation)
	int ret_x64 = detect_shellcode_x64(streamdata, size);

	// ARM32 and ARM64 detection with port-based filtering
	// Skip ARM detection for Windows-only services where ARM shellcode is impossible
	int ret_arm32 = -1;
	int ret_arm64 = -1;
	uint16_t dst_port = con->local.port;

	// Windows-only ports: SMB (445), RPC (135), NetBIOS (139), MSSQL (1433)
	if (dst_port != 445 && dst_port != 135 && dst_port != 139 && dst_port != 1433) {
		ret_arm32 = emu_shellcode_test_arm32(streamdata, size);
		ret_arm64 = emu_shellcode_test_arm64(streamdata, size);
	} else {
		g_debug("Skipping ARM detection on Windows-only port %d", dst_port);
	}

	// MIPS still uses pattern-based detection (TODO: add execution validation)
	int ret_mips = detect_shellcode_mips(streamdata, size);

	g_debug("Detection results: x86=%d x64=%d arm32=%d arm64=%d mips=%d",
	        ret_x86, ret_x64, ret_arm32, ret_arm64, ret_mips);

	// Update offset to end of scanned data (accounting for lookback)
	ctx->offset = offset + size;

	// Determine which architecture was detected (prefer earliest offset)
	int ret = -1;
	const char *arch = NULL;

	// Build array of results to find earliest match
	struct {
		int offset;
		const char *name;
	} results[] = {
		{ret_x86, "x86"},
		{ret_x64, "x86_64"},
		{ret_arm32, "arm32"},
		{ret_arm64, "arm64"},
		{ret_mips, "mips"},
	};

	for (size_t i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
		if (results[i].offset >= 0) {
			if (ret < 0 || results[i].offset < ret) {
				ret = results[i].offset;
				arch = results[i].name;
			}
		}
	}

	if (ret >= 0) {
		// Shellcode detected at offset ret
		g_info("Shellcode detected at offset %d (arch: %s, stream size: %d)",
		       ret, arch, size);

		// Save shellcode to disk (full stream with offset for decoder stub analysis)
		save_shellcode(streamdata, size, ret, arch, con);

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
