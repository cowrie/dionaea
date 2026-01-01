/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdbool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>


#include <sys/time.h>
#include <time.h>

#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#include <glib.h>

#define D_LOG_DOMAIN "connection"

#define CL g_dionaea->loop

#include "dionaea.h"
#include "connection.h"
#include "util.h"
#include "log.h"
#include "incident.h"
#include "processor.h"

/*
 * Loads a certificate chain from a file and adds it to the SSL context of the connection.
 * The certificates must be in the PEM format.
 *
 * @param con The connection
 * @param path The filepath of the certificate chain.
 *
 * @return true on success | false if something went wrong
 */
bool connection_tls_set_certificate(struct connection *con, const char *path)
{
	g_debug("%s con %p path %s",__PRETTY_FUNCTION__, con, path);
	int ret = SSL_CTX_use_certificate_chain_file(con->transport.tls.ctx, path);
	if( ret != 1 ) {
		perror("SSL_CTX_use_certificate_chain_file");
		return false;
	}
	return true;
}

/*
 * Loads the first private key from a file and adds it to the SSL context of the connection.
 *
 * @param con The connection
 * @param path The filepath of the certificate chain
 * @param type The type of the key. SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.
 *
 * @return true on success | false if something went wrong
 */
bool connection_tls_set_key(struct connection *con, const char *path, int type)
{
	g_debug("%s con %p path %s type %i",__PRETTY_FUNCTION__, con, path, type);
	int ret = SSL_CTX_use_PrivateKey_file(con->transport.tls.ctx, path, type);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_PrivateKey_file");
		return false;
	}
	return true;
}

bool connection_tls_mkcert(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);
	return mkcert(con->transport.tls.ctx);
}

void connection_tls_io_out_cb(EV_P_ struct ev_io *w, int revents)
{
	(void)revents;
	struct connection *con = NULL;
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);


	if( con->transport.tls.io_out_again->len == 0 )
	{
		GString *io_out_again = con->transport.tls.io_out_again;
		con->transport.tls.io_out_again = con->transport.tls.io_out;
		con->transport.tls.io_out = io_out_again;
		con->transport.tls.io_out_again_size = 0;
	}


	int send_throttle = connection_throttle(con, &con->stats.io_out.throttle);
	if( con->transport.tls.io_out_again_size == 0 )
		con->transport.tls.io_out_again_size = MIN((int)con->transport.tls.io_out_again->len, send_throttle);

	if( con->transport.tls.io_out_again_size <= 0 )
		return;

	g_debug("send_throttle %i con->transport.tcp.io_out_again->len %i con->transport.ssl.io_out_again_size %i todo %i",
			send_throttle, (int)con->transport.tls.io_out_again->len, con->transport.tls.io_out_again_size,
			(int)con->transport.tls.io_out_again->len + (int)con->transport.tls.io_out->len);


	int err = SSL_write(con->transport.tls.ssl, con->transport.tls.io_out_again->str, (int)con->transport.tls.io_out_again_size);
	connection_tls_error(con);

	if( err <= 0 )
	{
		int action = SSL_get_error(con->transport.tls.ssl, err);
		connection_tls_error(con);
		switch( action )
		{
		case SSL_ERROR_ZERO_RETURN:
			g_debug("SSL_ERROR_ZERO_RETURN");
			if( revents != 0 )
				connection_tls_disconnect(con);
			else
				connection_set_state(con, connection_state_close);
			break;

		case SSL_ERROR_WANT_READ:
			g_debug("SSL_ERROR_WANT_READ");

			if( ev_is_active(&con->events.io_in) && revents != EV_READ )
			{
				ev_io_stop(CL, &con->events.io_in);
				ev_io_init(&con->events.io_in, connection_tls_io_out_cb, con->socket, EV_READ);
				ev_io_start(CL, &con->events.io_in);
			}

			if( ev_is_active(&con->events.io_out) )
				ev_io_stop(CL, &con->events.io_out);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_ERROR_WANT_WRITE");
			if( !ev_is_active(&con->events.io_out) )
				ev_io_start(CL, &con->events.io_out);

			if( ev_is_active(&con->events.io_in) )
				ev_io_stop(CL, &con->events.io_in);
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT");
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP");
			break;

		case SSL_ERROR_SYSCALL:
			g_debug("SSL_ERROR_SYSCALL");
			connection_tls_disconnect(con);
			break;

		case SSL_ERROR_SSL:
			g_debug("SSL_ERROR_SSL");
			connection_tls_disconnect(con);
			break;

		case SSL_ERROR_NONE:
			g_debug("SSL_ERROR_NONE");
			break;

		}
	} else
	{
		int size = err;

		if( size == con->transport.tls.io_out_again_size )
		{
			/* restore io handlers to fit default */
			if( ev_is_active(&con->events.io_in) && ev_cb(&con->events.io_in) != connection_tls_io_in_cb )
				ev_io_stop(CL, &con->events.io_in);

			if( !ev_is_active(&con->events.io_in) )
			{
				ev_io_init(&con->events.io_in, connection_tls_io_in_cb, con->socket, EV_READ);
				ev_io_start(CL, &con->events.io_in);
			}

			if( ev_is_active(&con->events.io_out) && ev_cb(&con->events.io_out) != connection_tls_io_out_cb )
				ev_io_stop(CL, &con->events.io_out);

			if( !ev_is_active(&con->events.io_out) )
			{
				ev_io_init(&con->events.io_out, connection_tls_io_out_cb, con->socket, EV_WRITE);
				ev_io_start(CL, &con->events.io_out);
			}

			if( con->processor_data != NULL && size > 0 )
			{
				processors_io_out(con, con->transport.tls.io_out_again->str, size);
			}

			connection_throttle_update(con, &con->stats.io_out.throttle, size);

			g_string_erase(con->transport.tls.io_out_again, 0 , con->transport.tls.io_out_again_size);
			con->transport.tls.io_out_again_size = 0;

			if( con->transport.tls.io_out_again->len == 0 && con->transport.tls.io_out->len == 0 )
			{
				g_debug("connection is flushed");
				if( ev_is_active(&con->events.io_out) )
					ev_io_stop(EV_A_ &con->events.io_out);

				if( con->state == connection_state_close )
					connection_tls_shutdown_cb(EV_A_ w, revents);
				else
					if( con->protocol.io_out != NULL )
				{
					/* avoid recursion */
					connection_flag_set(con, connection_busy_sending);
					con->protocol.io_out(con, con->protocol.ctx);
					connection_flag_unset(con, connection_busy_sending);
					if( con->transport.tls.io_out->len > 0 )
						ev_io_start(CL, &con->events.io_out);
				}
			}



		} else
		{
			g_debug("unexpected state");
		}

	}
}


void connection_tls_shutdown_cb(EV_P_ struct ev_io *w, int revents)
{
	(void)revents;
	struct connection *con = NULL;
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);

	if( con->type == connection_type_listen )
	{
		g_debug("connection was listening, closing!");
		connection_tls_disconnect(con);
		return;
	}

	if( SSL_get_shutdown(con->transport.tls.ssl) & (SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN) )
	{
		g_debug("connection has sent&received shutdown");
		connection_tls_disconnect(con);
		return;
	}

	ev_io_stop(EV_A_ &con->events.io_in);
	ev_io_stop(EV_A_ &con->events.io_out);

	connection_tls_error(con);

	int err = SSL_shutdown(con->transport.tls.ssl);
	connection_tls_error(con);

	int action;

	switch( err )
	{
	case 1:
		connection_tls_disconnect(con);
		break;

	case 0:
		err = SSL_shutdown(con->transport.tls.ssl);
		action = SSL_get_error(con->transport.tls.ssl, err);
		connection_tls_error(con);

		switch( action )
		{
		case SSL_ERROR_WANT_READ:
			g_debug("SSL_ERROR_WANT_READ");
			ev_io_init(&con->events.io_in, connection_tls_shutdown_cb, con->socket, EV_READ);
			ev_io_start(EV_A_ &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_ERROR_WANT_WRITE");
			ev_io_init(&con->events.io_out, connection_tls_shutdown_cb, con->socket, EV_WRITE);
			ev_io_start(EV_A_ &con->events.io_out);
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT");
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP");
			break;

		case SSL_ERROR_SYSCALL:
			g_debug("SSL_ERROR_SYSCALL errno=%i (%s)", errno, strerror(errno));
			connection_tls_disconnect(con);
			break;

		case SSL_ERROR_SSL:
			g_debug("SSL_ERROR_SSL");
			connection_tls_disconnect(con);
			break;
		}

		break;

	case -1:
		g_debug("SSL_shutdown returned -1");
		action = SSL_get_error(con->transport.tls.ssl, err);
		connection_tls_error(con);

		switch( action )
		{
		case SSL_ERROR_WANT_READ:
			g_debug("SSL_ERROR_WANT_READ");
			ev_io_init(&con->events.io_in, connection_tls_shutdown_cb, con->socket, EV_READ);
			ev_io_start(EV_A_ &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_ERROR_WANT_WRITE");
			ev_io_init(&con->events.io_out, connection_tls_shutdown_cb, con->socket, EV_WRITE);
			ev_io_start(EV_A_ &con->events.io_out);
			break;

		default:
			g_debug("SSL_ERROR %i", action);
			connection_tls_disconnect(con);
			break;
		}
		break;

	default:
		g_debug("SSL_shutdown returned %i", err);
		break;
	}
}

void connection_tls_io_in_cb(EV_P_ struct ev_io *w, int revents)
{
	(void)revents;
	struct connection *con = NULL;

	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);

	g_debug("%s con %p",__PRETTY_FUNCTION__, con);


	int recv_throttle = connection_throttle(con, &con->stats.io_in.throttle);
	if( recv_throttle == 0 )
	{
		g_debug("recv throttle %i", recv_throttle);
		return;
	}
	// Explicitly cap to buffer size for safety
	int recv_size = MIN(recv_throttle, CONNECTION_MAX_RECV_SIZE);

	// Use fixed-size buffer instead of VLA to prevent stack exhaustion
	unsigned char buf[CONNECTION_MAX_RECV_SIZE];
	int err=0;
	if( (err = SSL_read(con->transport.tls.ssl, buf, recv_size)) > 0 )
	{
//		g_debug("SSL_read %i %.*s", err, err, buf);
		g_string_append_len(con->transport.tls.io_in, (gchar *)buf, err);
	}
	connection_tls_error(con);

	int action = SSL_get_error(con->transport.tls.ssl, err);
	connection_tls_error(con);

	if( err<=0 )
	{
		switch( action )
		{
		case SSL_ERROR_NONE:
			g_debug("SSL_ERROR_NONE");
			break;

		case SSL_ERROR_ZERO_RETURN:
			g_debug("SSL_ERROR_ZERO_RETURN");
			connection_tls_shutdown_cb(EV_A_ w, revents);
			break;

		case SSL_ERROR_WANT_READ:
			g_debug("SSL_ERROR_WANT_READ");
			if( ev_is_active(&con->events.io_out) )
				ev_io_stop(CL, &con->events.io_out);

			if( !ev_is_active(&con->events.io_in) )
				ev_io_start(CL, &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_ERROR_WANT_WRITE");
			if( ev_is_active(&con->events.io_in) )
				ev_io_stop(CL, &con->events.io_in);

			if( ev_is_active( &con->events.io_out ) && revents != EV_WRITE )
			{
				ev_io_stop(EV_A_ &con->events.io_out);
				ev_io_init(&con->events.io_out, connection_tls_io_in_cb, con->socket, EV_WRITE);
				ev_io_start(EV_A_ &con->events.io_out);
			}
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT");
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP");
			break;

		case SSL_ERROR_SYSCALL:
			if( err == 0 )
				g_debug("TLS protocol violation: remote %s:%s closed without proper shutdown (version: %s)",
					con->remote.ip_string,
					con->remote.port_string,
					SSL_get_version(con->transport.tls.ssl));
			else if( err == -1 )
				g_debug("TLS read failed: SYSCALL error (client %s:%s, errno: %d %s)",
					con->remote.ip_string,
					con->remote.port_string,
					errno, strerror(errno));

			connection_tls_disconnect(con);
			break;

		case SSL_ERROR_SSL:
			g_debug("TLS read failed: SSL error (client %s:%s, error: %s)",
				con->remote.ip_string,
				con->remote.port_string,
				con->transport.tls.ssl_error_string);
			connection_tls_disconnect(con);
			break;
		}
	} else
		if( err > 0 )
	{

		/* restore io handlers to fit default */
		if( ev_is_active(&con->events.io_in) && ev_cb(&con->events.io_in) != connection_tls_io_in_cb )
			ev_io_stop(CL, &con->events.io_in);

		if( !ev_is_active(&con->events.io_in) )
		{
			ev_io_init(&con->events.io_in, connection_tls_io_in_cb, con->socket, EV_READ);
			ev_io_start(CL, &con->events.io_in);
		}

		if( ev_is_active(&con->events.io_out) && ev_cb(&con->events.io_out) != connection_tls_io_out_cb )
			ev_io_stop(CL, &con->events.io_out);

		if( !ev_is_active(&con->events.io_out) )
		{
			ev_io_init(&con->events.io_out, connection_tls_io_out_cb, con->socket, EV_WRITE);
		}

		connection_throttle_update(con, &con->stats.io_in.throttle, err);

		if( ev_is_active(&con->events.idle_timeout) )
			ev_timer_again(EV_A_  &con->events.idle_timeout);

		if( con->processor_data != NULL && con->transport.tls.io_in->len > 0 )
                {
                    processors_io_in(con, con->transport.tls.io_in->str, (int)con->transport.tls.io_in->len);
                }

		con->protocol.io_in(con, con->protocol.ctx, (unsigned char *)con->transport.tls.io_in->str, con->transport.tls.io_in->len);
		con->transport.tls.io_in->len = 0;

		if( (con->transport.tls.io_out->len > 0 || con->transport.tls.io_out_again->len > 0 ) &&
			!ev_is_active(&con->events.io_out) )
			ev_io_start(EV_A_ &con->events.io_out);
	}
}

void connection_tls_accept_cb (EV_P_ struct ev_io *w, int revents)
{
	(void)revents;
	struct connection *con = CONOFF_IO_IN(w);
	struct incident *i;
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	while( 1 )
	{
		struct sockaddr_storage sa;
		socklen_t sizeof_sa = sizeof(struct sockaddr_storage);

		// clear accept timeout, reset


		int accepted_socket = accept(con->socket, (struct sockaddr *)&sa, &sizeof_sa);

		if( accepted_socket == -1 && (errno == EAGAIN || errno == EWOULDBLOCK) )
			break;


		if( accepted_socket > g_dionaea->limits.fds * 70/100 )
		{
			g_warning("Running out of fds, closing connection (fd %i limit %i applied limit %i)",
					  accepted_socket,
					  g_dionaea->limits.fds,
					  g_dionaea->limits.fds * 70/100);
			(void)close(accepted_socket);
			continue;
		}


		struct connection *accepted = connection_new(connection_transport_tls);
		SSL_CTX_free(accepted->transport.tls.ctx);
		connection_set_type(accepted, connection_type_accept);
		accepted->socket = accepted_socket;
		accepted->data = con->data;

		connection_node_set_local(accepted);
		connection_node_set_remote(accepted);

		g_debug("accept() %i local:'%s' remote:'%s'", accepted->socket, accepted->local.node_string,  accepted->remote.node_string);
		connection_set_nonblocking(accepted);

		// set protocol for accepted connection
		connection_protocol_set(accepted, &con->protocol);

		accepted->stats.io_out.throttle.max_bytes_per_second = con->stats.io_out.throttle.max_bytes_per_second;

		accepted->transport.tls.ctx = con->transport.tls.ctx;
		accepted->transport.tls.ssl = SSL_new(accepted->transport.tls.ctx);
		SSL_set_fd(accepted->transport.tls.ssl, accepted->socket);

		SSL_set_app_data(accepted->transport.tls.ssl, con);
//		SSL_set_app_data2(ssl, NULL); /* will be request_rec */

//		sslconn->ssl = ssl;

		/*
		 *  Configure DH parameters for SSL connection
		 */
//		memcpy(accepted->transport.ssl.pTmpKeys, con->transport.ssl.pTmpKeys, sizeof(void *)*SSL_TMP_KEY_MAX);
//		accepted->transport.ssl.parent = con;
		/* Use automatic DH parameter selection in OpenSSL 3.0+ */
		SSL_set_dh_auto(accepted->transport.tls.ssl, 1);


		ev_timer_init(&accepted->events.handshake_timeout, connection_tls_handshake_again_timeout_cb, 0., con->events.handshake_timeout.repeat);
//		ev_timer_init(&accepted->events.idle_timeout, connection_tls_accept_again_timeout_cb, 0., con->events.idle_timeout.repeat);


		// create protocol specific data
		accepted->protocol.ctx = accepted->protocol.ctx_new(accepted);


		accepted->stats.io_in.throttle.max_bytes_per_second = con->stats.io_in.throttle.max_bytes_per_second;
		accepted->stats.io_out.throttle.max_bytes_per_second = con->stats.io_out.throttle.max_bytes_per_second;

		// teach new connection about parent
		if( con->protocol.origin != NULL )
			con->protocol.origin(accepted, con);

		connection_set_state(accepted, connection_state_handshake);
		SSL_set_accept_state(accepted->transport.tls.ssl);

		accepted->events.io_in.events = EV_READ;
		connection_tls_handshake_again_cb(EV_A_ &accepted->events.io_in, 0);

		i = incident_new("dionaea.connection.link");
		incident_value_con_set(i, "parent", con);
		incident_value_con_set(i, "child", accepted);
		incident_report(i);
		incident_free(i);
	}

	if( ev_is_active(&con->events.listen_timeout) )
	{
		ev_clear_pending(EV_A_ &con->events.listen_timeout);
		ev_timer_again(EV_A_  &con->events.listen_timeout);
	}
}


void connection_tls_handshake_again_cb(EV_P_ struct ev_io *w, int revents)
{
	struct connection *con = NULL;
	struct incident *i;

	if( w->events == EV_READ )
		con = CONOFF_IO_IN(w);
	else
		con	= CONOFF_IO_OUT(w);
	g_debug("%s con %p %i %p %p",__PRETTY_FUNCTION__, con, revents, CONOFF_IO_IN(w), CONOFF_IO_OUT(w));

	ev_io_stop(EV_A_ &con->events.io_in);
	ev_io_stop(EV_A_ &con->events.io_out);

	int err = SSL_do_handshake(con->transport.tls.ssl);
	connection_tls_error(con);
	if( err != 1 )
	{
		g_debug("setting connection_tls_accept_again_timeout_cb to %f",con->events.handshake_timeout.repeat);
		ev_timer_again(EV_A_ &con->events.handshake_timeout);

		int action = SSL_get_error(con->transport.tls.ssl, err);
		g_debug("SSL_do_handshake: %s",
			action == SSL_ERROR_WANT_READ ? "WANT_READ" :
			action == SSL_ERROR_WANT_WRITE ? "WANT_WRITE" :
			action == SSL_ERROR_SYSCALL ? "SYSCALL" :
			action == SSL_ERROR_SSL ? "SSL_ERROR" : "OTHER");

		connection_tls_error(con);
		switch( action )
		{
		case SSL_ERROR_NONE:
			g_debug("SSL_ERROR_NONE");
			break;
		case SSL_ERROR_ZERO_RETURN:
			g_debug("SSL_ERROR_ZERO_RETURN");
			break;

		case SSL_ERROR_WANT_READ:
			g_debug("SSL_ERROR_WANT_READ");
			ev_io_init(&con->events.io_in, connection_tls_handshake_again_cb, con->socket, EV_READ);
			ev_io_start(EV_A_ &con->events.io_in);
			break;

		case SSL_ERROR_WANT_WRITE:
			g_debug("SSL_ERROR_WANT_WRITE");
			ev_io_init(&con->events.io_out, connection_tls_handshake_again_cb, con->socket, EV_WRITE);
			ev_io_start(EV_A_ &con->events.io_out);
			break;

		case SSL_ERROR_WANT_ACCEPT:
			g_debug("SSL_ERROR_WANT_ACCEPT");
			break;

		case SSL_ERROR_WANT_X509_LOOKUP:
			g_debug("SSL_ERROR_WANT_X509_LOOKUP");
			break;

		case SSL_ERROR_SYSCALL:
			if( errno == 0 )
				/* errno 0 means peer disconnected (EOF) without close_notify - common for scanners */
				g_info("TLS handshake: peer %s:%s disconnected (version: %s, state: %s)",
					con->remote.ip_string,
					con->remote.port_string,
					SSL_get_version(con->transport.tls.ssl),
					SSL_state_string_long(con->transport.tls.ssl));
			else
				g_warning("TLS handshake failed: SYSCALL error (client %s:%s, errno: %d %s, version: %s, state: %s)",
					con->remote.ip_string,
					con->remote.port_string,
					errno, strerror(errno),
					SSL_get_version(con->transport.tls.ssl),
					SSL_state_string_long(con->transport.tls.ssl));
			connection_tls_disconnect(con);
			break;

		case SSL_ERROR_SSL:
			g_warning("TLS handshake failed: SSL error (client %s:%s, error: %s, version: %s, state: %s)",
				con->remote.ip_string,
				con->remote.port_string,
				con->transport.tls.ssl_error_string,
				SSL_get_version(con->transport.tls.ssl),
				SSL_state_string_long(con->transport.tls.ssl));
			connection_tls_disconnect(con);
			break;
		}
	} else
	{
		g_debug("SSL_do_handshake success");
		ev_timer_stop(EV_A_ &con->events.handshake_timeout);
		ev_timer_init(&con->events.idle_timeout, connection_idle_timeout_cb, 0. ,con->events.idle_timeout.repeat);
		connection_established(con);

		i = incident_new("dionaea.connection.tls.accept");
		incident_value_con_set(i, "con", con);
		incident_report(i);
		incident_free(i);
	}
}

void connection_tls_handshake_again_timeout_cb(EV_P_ struct ev_timer *w, int revents)
{
	(void)revents;
	struct connection *con = CONOFF_HANDSHAKE_TIMEOUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	switch( con->type )
	{
	case connection_type_connect:
		g_warning("TLS handshake timeout (outbound to %s:%s, version: %s, state: %s)",
			con->remote.ip_string,
			con->remote.port_string,
			SSL_get_version(con->transport.tls.ssl),
			SSL_state_string_long(con->transport.tls.ssl));
		ev_timer_stop(EV_A_ &con->events.handshake_timeout);
		ev_io_stop(EV_A_ &con->events.io_out);
		(void)close(con->socket);
		con->socket = -1;
		connection_connect_next_addr(con);
		break;
	case connection_type_accept:
		g_warning("TLS handshake timeout (inbound from %s:%s, version: %s, state: %s)",
			con->remote.ip_string,
			con->remote.port_string,
			SSL_get_version(con->transport.tls.ssl),
			SSL_state_string_long(con->transport.tls.ssl));
		connection_tls_disconnect(con);
		break;
	case connection_type_listen:
	case connection_type_bind:
	case connection_type_none:
		break;
	}
}

void connection_tls_disconnect(struct connection *con)
{
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	enum connection_state state = con->state;
	connection_set_state(con, connection_state_close);

	connection_disconnect(con);

	g_string_erase(con->transport.tls.io_in, 0, -1);
	g_string_erase(con->transport.tls.io_out, 0, -1);
	g_string_erase(con->transport.tls.io_out_again, 0, -1);
	con->transport.tls.io_out_again_size = 0;


	if( con->protocol.disconnect != NULL &&
		(state != connection_state_none &&
		 state != connection_state_connecting &&
		 state != connection_state_handshake) )
	{
		bool reconnect = con->protocol.disconnect(con, con->protocol.ctx);
		g_debug("reconnect is %i", reconnect);
		if( reconnect == true && con->type == connection_type_connect )
		{
			connection_reconnect(con);
			return;
		}
	}
	connection_free(con);
}

void connection_tls_connecting_cb(EV_P_ struct ev_io *w, int revents)
{
	(void)revents;
	struct connection *con = CONOFF_IO_OUT(w);
	g_debug("%s con %p",__PRETTY_FUNCTION__, con);

	ev_timer_stop(EV_A_ &con->events.connecting_timeout);

	int socket_error = 0;
	int error_size = sizeof(socket_error);


	int ret = getsockopt(con->socket, SOL_SOCKET, SO_ERROR, &socket_error,(socklen_t *)&error_size);

	if( ret != 0 || socket_error != 0 )
	{
		errno = socket_error;
		ev_io_stop(EV_A_ &con->events.io_out);
		(void)close(con->socket);
		connection_connect_next_addr(con);
		return;
	}

	connection_node_set_local(con);
	connection_node_set_remote(con);

	g_debug("connection %s -> %s", con->local.node_string, con->remote.node_string);

	if( con->transport.tls.ssl != NULL )
		SSL_free(con->transport.tls.ssl);

	con->transport.tls.ssl = SSL_new(con->transport.tls.ctx);
	SSL_set_fd(con->transport.tls.ssl, con->socket);

	ev_timer_init(&con->events.handshake_timeout, connection_tls_handshake_again_timeout_cb, 0., con->events.handshake_timeout.repeat);

	connection_set_state(con, connection_state_handshake);

	SSL_set_connect_state(con->transport.tls.ssl);

	con->events.io_in.events = EV_READ;
	connection_tls_handshake_again_cb(EV_A_ &con->events.io_in, 0);
}

void connection_tls_error(struct connection *con)
{
	con->transport.tls.ssl_error = ERR_get_error();
	ERR_error_string(con->transport.tls.ssl_error, con->transport.tls.ssl_error_string);
	if( con->transport.tls.ssl_error != 0 ) {
		if( strstr(con->transport.tls.ssl_error_string, "no suitable signature algorithm") != NULL ) {
			const char *version = SSL_get_version(con->transport.tls.ssl);

			/* Build list of client's signature algorithms */
			char sigalgs_buf[512] = "";
			int sigalgs_len = 0;
			int nsig = SSL_get_sigalgs(con->transport.tls.ssl, -1, NULL, NULL, NULL, NULL, NULL);
			for( int i = 0; i < nsig && sigalgs_len < 480; i++ ) {
				int sign_nid, hash_nid;
				SSL_get_sigalgs(con->transport.tls.ssl, i, &sign_nid, &hash_nid, NULL, NULL, NULL);
				const char *sign_name = OBJ_nid2sn(sign_nid);
				const char *hash_name = OBJ_nid2sn(hash_nid);
				int written = snprintf(sigalgs_buf + sigalgs_len, sizeof(sigalgs_buf) - (size_t)sigalgs_len,
					"%s%s+%s", sigalgs_len > 0 ? "," : "", hash_name ? hash_name : "?", sign_name ? sign_name : "?");
				if( written > 0 )
					sigalgs_len += written;
			}

			g_warning("SSL handshake failed: %s (client %s:%s, version: %s, client_sigalgs: %s)",
				con->transport.tls.ssl_error_string,
				con->remote.ip_string,
				con->remote.port_string,
				version ? version : "unknown",
				sigalgs_len > 0 ? sigalgs_buf : "none");
		} else {
			g_debug("SSL ERROR %s\t%s", con->transport.tls.ssl_error_string, SSL_state_string_long(con->transport.tls.ssl));
		}
	}
}
