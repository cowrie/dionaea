// ABOUTME: Dionaea module registration for Speakeasy shellcode detector
// ABOUTME: Registers the processor with dionaea's plugin system

/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 * SPDX-FileCopyrightText: 2024 Michel Oosterhof
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <stdio.h>

#include "modules.h"
#include "connection.h"
#include "dionaea.h"

#include "module.h"
#include "log.h"
#include "processor.h"

#define D_LOG_DOMAIN "speakeasy"

static bool speakeasy_config(void)
{
	return true;
}

static bool speakeasy_new(struct dionaea *d)
{
	// Register the speakeasy processor with dionaea
	g_hash_table_insert(g_dionaea->processors->names,
	                    (void *)proc_speakeasy.name,
	                    &proc_speakeasy);

	// Load shellcode storage directory from config
	GError *error = NULL;
	gchar *download_dir = g_key_file_get_string(g_dionaea->config, "dionaea", "download.dir", &error);
	if (download_dir != NULL) {
		speakeasy_set_shellcode_dir(download_dir);
		g_info("Shellcode storage directory: %s", download_dir);
		g_free(download_dir);
	} else {
		g_warning("download.dir not configured, shellcode will not be saved");
		if (error != NULL) {
			g_error_free(error);
		}
	}

	g_info("Speakeasy shellcode detector registered");
	return true;
}

static bool speakeasy_free(void)
{
	return true;
}

static bool speakeasy_hup(void)
{
	return true;
}

/**
 * Module initialization entry point
 * Called by dionaea when loading the module
 */
struct module_api *module_init(struct dionaea *d)
{
	g_debug("%s:%i %s dionaea %p", __FILE__, __LINE__, __PRETTY_FUNCTION__, d);

	static struct module_api speakeasy_api = {
		.config = &speakeasy_config,
		.start = NULL,
		.new = &speakeasy_new,
		.free = &speakeasy_free,
		.hup = &speakeasy_hup
	};

	return &speakeasy_api;
}
