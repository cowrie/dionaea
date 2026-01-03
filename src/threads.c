/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <glib.h>
#include <ev.h>
#include <unistd.h>


#include "dionaea.h"
#include "threads.h"
#include "log.h"
#include "incident.h"
#include "connection.h"

#define D_LOG_DOMAIN "thread"


void threadpool_wrapper(gpointer data, gpointer user_data)
{
	(void)user_data;
	struct thread *t = data;
#ifdef DEBUG
	GTimer *timer = g_timer_new();
#endif
	t->function(t->con, t->data);
#ifdef DEBUG
	g_timer_stop(timer);
	g_debug("Thread fn %p con %p data %p took %f ms", t->function, t->con, t->data, g_timer_elapsed(timer, NULL));
	g_timer_destroy(timer);
#endif
	g_free(data);
}

void trigger_cb(struct ev_loop *loop, struct ev_async *w, int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	struct async_cmd *cmd;
	while( (cmd = g_async_queue_try_pop(aq)) != NULL )
	{
		cmd->function(cmd->data);
		g_free(cmd);
	}
	g_async_queue_unref(aq);
}

void surveillance_cb(struct ev_loop *loop, struct ev_periodic *w, int revents)
{
	(void)loop;
	(void)w;
	(void)revents;

	static gboolean was_crowded = FALSE;
	static time_t last_log_time = 0;

	gint unprocessed = g_thread_pool_unprocessed(g_dionaea->threads->pool);
	gint max_threads = g_thread_pool_get_max_threads(g_dionaea->threads->pool);
	gint running = g_thread_pool_get_num_threads(g_dionaea->threads->pool);

	while( unprocessed > max_threads )
	{
		time_t now = time(NULL);

		// Log on state change or every 30 seconds while crowded
		if( !was_crowded || (now - last_log_time >= 30) )
		{
			g_warning("Threadpool crowded: %i queued, %i running, %i max - suspending activity",
					   unprocessed, running, max_threads);
			was_crowded = TRUE;
			last_log_time = now;
		}

		sleep(1);

		// Refresh counts after sleep
		unprocessed = g_thread_pool_unprocessed(g_dionaea->threads->pool);
		max_threads = g_thread_pool_get_max_threads(g_dionaea->threads->pool);
		running = g_thread_pool_get_num_threads(g_dionaea->threads->pool);
	}

	if( was_crowded && unprocessed <= max_threads )
	{
		g_message("Threadpool recovered: %i queued, %i running, %i max",
				   unprocessed, running, max_threads);
		was_crowded = FALSE;
	}
}


struct thread *thread_new(struct connection *con, void *data, GFunc function)
{
	struct thread *t = g_malloc0(sizeof(struct thread));
	t->con = con;
	t->data = data;
	t->function = function;
	return t;
}


struct async_cmd *async_cmd_new(async_cmd_cb function, void *data)
{
	struct async_cmd *cmd = g_malloc0(sizeof(struct async_cmd));
	cmd->data = data;
	cmd->function = function;
	return cmd;
}

void async_incident_report(void *data)
{
	struct incident *i = data;
	incident_report(i);
	struct connection *con;
	if( incident_value_con_get(i, "con", &con ) )
		connection_unref(con);
	incident_free(i);
}
