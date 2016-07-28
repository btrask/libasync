// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "uv/include/uv.h"
#include "../async.h"
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
	uv_tcp_t socket[1];
	struct tls *secure;
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
	assertf(!server->socket->data, "HTTPServer already listening");
	int rc = 0;

	server->socket->data = server;
	rc = uv_tcp_init(async_loop, server->socket);
	if(rc < 0) goto cleanup;

	// Tried getaddrinfo(3) but it seems remarkably disappointing.
	rc = UV_EADDRNOTAVAIL;
	if(rc < 0) {
		char const *name = address;
		if(!name) name = "::";
		else if(0 == strcmp("localhost", name)) name = "::1";
		struct sockaddr_in6 addr[1];
		rc = uv_ip6_addr(name, port, addr);
		if(rc >= 0) rc = uv_tcp_bind(server->socket, (struct sockaddr const *)addr, 0);
	}
	if(rc < 0) {
		char const *name = address;
		if(!name) name = "0.0.0.0";
		else if(0 == strcmp("localhost", name)) name = "127.0.0.1";
		struct sockaddr_in addr[1];
		rc = uv_ip4_addr(name, port, addr);
		if(rc >= 0) rc = uv_tcp_bind(server->socket, (struct sockaddr const *)addr, 0);
	}
	if(rc < 0) goto cleanup;

	rc = uv_listen((uv_stream_t *)server->socket, 511, connection_cb);
	if(rc < 0) goto cleanup;

cleanup:
	if(rc < 0) HTTPServerClose(server);
	return rc;
}
int HTTPServerListenSecure(HTTPServerRef const server, char const *const address, int const port, struct tls **const tlsptr) {
	if(!server) return 0;
	int rc = HTTPServerListen(server, address, port);
	if(rc < 0) return rc;
	server->secure = *tlsptr; *tlsptr = NULL;
	return 0;
}
int HTTPServerListenSecurePaths(HTTPServerRef const server, char const *const address, int const port, char const *const keypath, char const *const crtpath) {
	if(!server) return 0;
	if(!keypath) return UV_EINVAL;
	if(!crtpath) return UV_EINVAL;
	struct tls_config *config = NULL;
	struct tls *tls = NULL;
	int rc = 0;

	config = tls_config_new();
	if(!config) rc = -errno;
	if(!config && 0 == rc) rc = -ENOMEM;
	if(rc < 0) goto cleanup;

	rc = tlserr(tls_config_set_ciphers(config, TLS_CIPHERS));
	if(rc < 0) goto cleanup;
	tls_config_set_protocols(config, TLS_PROTOCOLS);
	rc = tlserr(tls_config_set_key_file(config, keypath));
	if(rc < 0) goto cleanup;
	rc = tlserr(tls_config_set_cert_file(config, crtpath));
	if(rc < 0) goto cleanup;

	tls = tls_server();
	if(!tls) rc = -errno;
	if(!tls && 0 == rc) rc = -ENOMEM;
	if(rc < 0) goto cleanup;
	rc = tlserr(tls_configure(tls, config));
	if(rc < 0) {
		//alogf("TLS config error: %s\n", tls_error(tls));
		goto cleanup;
	}

	rc = HTTPServerListenSecure(server, address, port, &tls);
	if(rc < 0) goto cleanup;

cleanup:
	tls_config_free(config); config = NULL;
	tls_free(tls); tls = NULL;
	return rc;
}
void HTTPServerClose(HTTPServerRef const server) {
	if(!server) return;
	if(server->secure) tls_close(server->secure);
	tls_free(server->secure); server->secure = NULL;
	async_close((uv_handle_t *)server->socket);
	server->socket->data = NULL;
}

static void connection(uv_stream_t *const socket) {
	HTTPServerRef const server = socket->data;
	HTTPConnectionRef conn;
	int rc = HTTPConnectionCreateIncomingSecure(socket, server->secure, 0, &conn);
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

