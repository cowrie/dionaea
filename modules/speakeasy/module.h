// ABOUTME: Header for minimal shellcode detection processor using Speakeasy
// ABOUTME: Defines structures and functions for detecting shellcode patterns

/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 * SPDX-FileCopyrightText: 2024 Michel Oosterhof
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_MODULE_SPEAKEASY_H
#define HAVE_MODULE_SPEAKEASY_H

struct connection;
struct processor_data;

/**
 * Per-connection context for shellcode detection
 * Tracks the offset in the stream to avoid re-scanning
 */
struct speakeasy_ctx
{
	int offset;  // Current offset in the stream
};

// Processor callbacks
void *proc_speakeasy_ctx_new(void *cfg);
void proc_speakeasy_ctx_free(void *ctx);
void *proc_speakeasy_ctx_cfg_new(gchar *group_name);
void proc_speakeasy_on_io_in(struct connection *con, struct processor_data *pd);

// Shellcode storage initialization
void speakeasy_set_shellcode_dir(const char *dir);

// Processor definition (defined in detect.c)
extern struct processor proc_speakeasy;

#endif
