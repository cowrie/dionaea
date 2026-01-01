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

#include <openssl/x509v3.h>

#include <glib.h>

#include "dionaea.h"
#include "connection.h"


static int add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions. */
	/* No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL
	 */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if( !ex )
		return 0;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);
	return 1;
}
/* TODO: Rewrite
static void callback(int p, int n, void *arg)
{
	char c='B';

	if( p == 0 ) c='.';
	if( p == 1 ) c='+';
	if( p == 2 ) c='*';
	if( p == 3 ) c='\n';
	fputc(c,stderr);
}
*/


bool mkcert(SSL_CTX *ctx)
{
	int bits = 512*4;
	long serial = time(NULL);
	int days = 365;
	gchar *value = NULL;
	GError *error = NULL;

	int ret = 0;
	bool res = false;

	X509 *x;
	EVP_PKEY *pk = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	X509_NAME *name=NULL;

	if( (x=X509_new()) == NULL )
		goto free_all;

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	if (pctx == NULL)
		goto free_all;

	if (EVP_PKEY_keygen_init(pctx) <= 0)
		goto free_all;

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits) <= 0)
		goto free_all;

	if (EVP_PKEY_keygen(pctx, &pk) <= 0) {
		g_error("Init: Failed to generate temporary %d bit RSA private key", bits);
		goto free_all;
	}

	X509_set_version(x,2);
	ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
	X509_set_pubkey(x,pk);

	name=X509_get_subject_name(x);

	value = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.c", &error);
	if (value == NULL) {
		value = g_strdup("DE");
	}
	g_clear_error(&error);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)value, -1, -1, 0);
	g_free(value);

	value = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.cn", &error);
	if (value == NULL) {
		value = g_strdup("Nepenthes Development Team");
	}
	g_clear_error(&error);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)value, -1, -1, 0);
	g_free(value);

	value = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.o", &error);
	if (value == NULL) {
		value = g_strdup("dionaea.carnivore.it");
	}
	g_clear_error(&error);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)value, -1, -1, 0);
	g_free(value);

	value = g_key_file_get_string(g_dionaea->config, "dionaea", "ssl.default.ou", &error);
	if (value == NULL) {
		value = g_strdup("anv");
	}
	g_clear_error(&error);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)value, -1, -1, 0);
	g_free(value);


	/* Its self signed so set the issuer name to be the same as the
	 * subject.
	 */
	X509_set_issuer_name(x,name);

	add_ext(x, NID_netscape_cert_type, "server");
	add_ext(x, NID_netscape_ssl_server_name, "localhost");

	if( !X509_sign(x,pk,EVP_sha256()) )
		goto free_all;


	ret = SSL_CTX_use_PrivateKey(ctx, pk);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_PrivateKey");
		goto free_all;
	}

	ret = SSL_CTX_use_certificate(ctx, x);
	if( ret != 1 )
	{
		perror("SSL_CTX_use_certificate");
		goto free_all;
	}

	res = true;
free_all:
	EVP_PKEY_CTX_free(pctx);

	return res;
}
