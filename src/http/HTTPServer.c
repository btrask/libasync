// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "uv/include/uv.h"
#include "libressl-portable/include/tls.h"
#include "HTTPServer.h"
#include "../util/common.h"

// You may need to set this to AF_INET6 to enable IPv6 on some systems.
#define LISTEN_FAMILY AF_UNSPEC

static int tlserr(int const x) {
	if(0 == x) return 0;
	if(errno) return -errno;
	return -1;
}

struct HTTPServer {
	HTTPListener listener;
	void *context;
	async_tls_t socket[1];
};

static void connection_cb(uv_stream_t *const socket, int const status);

int HTTPServerCreate(HTTPListener const listener, void *const context, HTTPServerRef *const out) {
	assertf(listener, "HTTPServer listener required");
	HTTPServerRef server = calloc(1, sizeof(struct HTTPServer));
	if(!server) return UV_ENOMEM;
	server->listener = listener;
	server->context = context;
	*out = server; server = NULL;
	return 0;
}
void HTTPServerFree(HTTPServerRef *const serverptr) {
	HTTPServerRef server = *serverptr; *serverptr = NULL;
	if(!server) return;
	HTTPServerClose(server);
	server->listener = NULL;
	server->context = NULL;
	assert_zeroed(server, 1);
	FREE(&server);
}

int HTTPServerListen(HTTPServerRef const server, char const *const address, int const port) {
	if(!server) return 0;
	assertf(!server->socket->stream->data, "HTTPServer already listening");
	int rc = 0;

	server->socket->stream->data = server;
	rc = uv_tcp_init(async_loop, server->socket->stream);
	if(rc < 0) goto cleanup;

	// Tried getaddrinfo(3) but it seems remarkably disappointing.
	rc = UV_EADDRNOTAVAIL;
	if(rc < 0) {
		char const *name = address;
		if(!name) name = "::";
		if(0 == strcmp("localhost", name)) name = "::1";
		struct sockaddr_in6 addr[1];
		rc = uv_ip6_addr(name, port, addr);
		if(rc >= 0) rc = uv_tcp_bind(server->socket->stream, (struct sockaddr const *)addr, 0);
	}
	if(rc < 0) {
		char const *name = address;
		if(!name) name = "0.0.0.0";
		if(0 == strcmp("localhost", name)) name = "127.0.0.1";
		struct sockaddr_in addr[1];
		rc = uv_ip4_addr(name, port, addr);
		if(rc >= 0) rc = uv_tcp_bind(server->socket->stream, (struct sockaddr const *)addr, 0);
	}
	if(rc < 0) goto cleanup;

	rc = uv_listen((uv_stream_t *)server->socket->stream, 511, connection_cb);
	if(rc < 0) goto cleanup;

cleanup:
	if(rc < 0) HTTPServerClose(server);
	return rc;
}
int HTTPServerListenSecurePaths(HTTPServerRef const server, char const *const address, int const port, char const *const keypath, char const *const crtpath) {
	if(!server) return 0;
	if(!keypath) return UV_EINVAL;
	if(!crtpath) return UV_EINVAL;
	struct tls_config *config = NULL;
	struct tls *tls = NULL;
	int rc = 0;

	errno = 0;
	config = tls_config_new();
	if(!config) rc = -errno < 0 ? -errno : -ENOMEM;
	if(rc < 0) goto cleanup;

	rc = tlserr(tls_config_set_ciphers(config, ASYNC_TLS_CIPHERS));
	if(rc < 0) goto cleanup;
	tls_config_set_protocols(config, ASYNC_TLS_PROTOCOLS);
	rc = tlserr(tls_config_set_key_file(config, keypath));
	if(rc < 0) goto cleanup;
	rc = tlserr(tls_config_set_cert_file(config, crtpath));
	if(rc < 0) goto cleanup;

	errno = 0;
	tls = tls_server();
	if(!tls) rc = -errno < 0 ? -errno : -ENOMEM;
	if(rc < 0) goto cleanup;
	rc = tlserr(tls_configure(tls, config));
	if(rc < 0) goto cleanup;

	rc = HTTPServerListen(server, address, port);
	if(rc < 0) goto cleanup;

	server->socket->secure = tls; tls = NULL;

cleanup:
	tls_config_free(config); config = NULL;
	tls_free(tls); tls = NULL;
	return rc;
}
void HTTPServerClose(HTTPServerRef const server) {
	if(!server) return;
	async_tls_close(server->socket);
	server->socket->stream->data = NULL;
}

static void connection(uv_stream_t *const x) {
	HTTPServerRef const server = x->data;
	HTTPConnectionRef conn;
	int rc = HTTPConnectionAccept(server->socket, 0, &conn);
	if(UV_EOF == rc) return;
	if(rc < 0) {
//		alogf("Incoming connection error: %s\n", uv_strerror(rc));
		return;
	}
	assert(conn);

	for(;;) {
		server->listener(server->context, server, conn);
		rc = HTTPConnectionDrainMessage(conn);
		if(rc < 0) break;
	}

	HTTPConnectionFree(&conn);
}
static void connection_cb(uv_stream_t *const socket, int const status) {
	async_spawn(STACK_DEFAULT, (void (*)())connection, socket);
}

