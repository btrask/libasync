// Copyright 2015-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "libressl-portable/include/tls.h"
#include "async_tls.h"
#include "util/common.h"

static int tlserr(int const rc, struct tls *const secure) {
	if(0 == rc) return 0;
	assert(-1 == rc);
//	fprintf(stderr, "TLS error: %s\n", tls_error(secure));
	return UV_EPROTO;
}
static int tls_poll(uv_stream_t *const stream, int const event) {
	int rc;
	if(TLS_WANT_POLLIN == event) {
		rc = async_read(stream, NULL, 0);
		if(UV_ENOBUFS == rc) rc = 0;
	} else if(TLS_WANT_POLLOUT == event) {
		// TODO: libuv provides NO WAY to wait until a stream is
		// writable! Even our zero-length write hack doesn't work.
		// uv_poll can't be used on uv's own stream fds.
		rc = async_sleep(50);
	} else {
		rc = event;
	}
	return rc;
}

int async_tls_accept(async_tls_t *const server, async_tls_t *const socket) {
	if(!server) return UV_EINVAL;
	if(!socket) return UV_EINVAL;
	memset(socket, 0, sizeof(async_tls_t));
	int rc = uv_tcp_init(async_loop, socket->stream);
	if(rc < 0) goto cleanup;
	rc = uv_accept((uv_stream_t *)server->stream, (uv_stream_t *)socket->stream);
	if(rc < 0) goto cleanup;
	if(server->secure) {
		uv_os_fd_t fd;
		rc = uv_fileno((uv_handle_t *)socket->stream, &fd);
		if(rc < 0) goto cleanup;
		rc = tlserr(tls_accept_socket(server->secure, (struct tls **)&socket->secure, fd), server->secure);
		if(rc < 0) goto cleanup;
		for(;;) {
			int event = tls_handshake(socket->secure);
			if(0 == event) break;
			rc = tlserr(tls_poll((uv_stream_t *)socket->stream, event), socket->secure);
			if(rc < 0) goto cleanup;
		}
	}
cleanup:
	if(rc < 0) async_tls_close(socket);
	return rc;
}
int async_tls_connect(char const *const host, char const *const port, bool const secure, async_tls_t *const socket) {
	if(!socket) return UV_EINVAL;
	struct addrinfo *info = NULL;
	struct tls_config *config = NULL;
	int rc;
	memset(socket, 0, sizeof(async_tls_t));

	struct addrinfo const hints = {
		.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_NUMERICSERV,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0, // ???
	};
	rc = async_getaddrinfo(host, port, &hints, &info);
	if(rc < 0) goto cleanup;

	rc = UV_EADDRNOTAVAIL;
	for(struct addrinfo *each = info; each; each = each->ai_next) {
		rc = uv_tcp_init(async_loop, socket->stream);
		if(rc < 0) goto cleanup;
		rc = async_tcp_connect(socket->stream, each->ai_addr);
		if(rc >= 0) break;
		async_close((uv_handle_t *)socket->stream);
	}

	if(secure) {
		config = tls_config_new();
		if(!config) rc = UV_ENOMEM;
		if(rc < 0) goto cleanup;

		socket->secure = tls_client();
		if(!socket->secure) rc = UV_ENOMEM;
		if(rc < 0) goto cleanup;
		rc = tls_configure(socket->secure, config);
		if(rc < 0) goto cleanup;
		uv_os_fd_t fd;
		rc = uv_fileno((uv_handle_t *)socket->stream, &fd);
		if(rc < 0) goto cleanup;
		rc = tlserr(tls_connect_socket(socket->secure, fd, host), socket->secure);
		if(rc < 0) goto cleanup;
		for(;;) {
			int event = tls_handshake(socket->secure);
			if(0 == event) break;
			rc = tlserr(tls_poll((uv_stream_t *)socket->stream, event), socket->secure);
			if(rc < 0) goto cleanup;
		}
	}

cleanup:
	tls_config_free(config); config = NULL;
	uv_freeaddrinfo(info); info = NULL;
	if(rc < 0) async_tls_close(socket);
	return rc;
}
void async_tls_close(async_tls_t *const socket) {
	if(!socket) return;
	if(socket->secure) tls_close(socket->secure);
	tls_free(socket->secure); socket->secure = NULL;
	async_close((uv_handle_t *)socket->stream);
	assert_zeroed(socket, 1);
}
bool async_tls_is_secure(async_tls_t *const socket) {
	if(!socket) return false;
	return !!socket->secure;
}
char const *async_tls_error(async_tls_t *const socket) {
	if(!socket) return NULL;
	if(!socket->secure) return NULL;
	return tls_error(socket->secure);
}

ssize_t async_tls_read(async_tls_t *const socket, unsigned char *const buf, size_t const max) {
	if(!socket->secure) {
		return async_read((uv_stream_t *)socket->stream, buf, max);
	}

	for(;;) {
		ssize_t x = tls_read(socket->secure, buf, max);
		if(x >= 0) return x;
		int rc = tlserr(tls_poll((uv_stream_t *)socket->stream, (int)x), socket->secure);
		if(rc < 0) return rc;
	}
	assert(0);
	return UV_UNKNOWN; // Not reached
}
ssize_t async_tls_write(async_tls_t *const socket, unsigned char const *const buf, size_t const len) {
	if(!socket->secure) {
		return async_write((uv_stream_t *)socket->stream, buf, len);
	}

	for(;;) {
		ssize_t x = tls_write(socket->secure, buf, len);
		if(x >= 0) return x;
		int rc = tlserr(tls_poll((uv_stream_t *)socket->stream, (int)x), socket->secure);
		if(rc < 0) return rc;
	}
	assert(0);
	return UV_UNKNOWN; // Not reached
}

