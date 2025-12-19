/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DIONAEA_UTIL_H
#define DIONAEA_UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

void *addr_offset(const void *x);
unsigned int addr_size(const void *x);
void *port_offset(const void *x);

bool sockaddr_storage_from(struct sockaddr_storage *ss, int family, void *host, uint16_t port);
bool parse_addr(char const * const addr, char const * const iface, uint16_t const port, struct sockaddr_storage * const sa, int * const socket_domain, socklen_t * const sizeof_sa);

int ipv6_addr_linklocal(struct in6_addr const * const a);
int ipv6_addr_v4mapped(struct in6_addr const * const a);

struct tempfile
{
	int fd;
	FILE *fh;
	char *path;
};

struct tempfile *tempfile_new(char *path, char *prefix);
struct tempfile *tempdownload_new(char *prefix);
void tempfile_close(struct tempfile *tf);
void tempfile_unlink(struct tempfile *tf);
void tempfile_free(struct tempfile *tf);

#endif /* DIONAEA_UTIL_H */
