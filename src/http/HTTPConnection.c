// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "Socket.h"
#include "HTTP.h"
#include "status.h"
#include "../util/common.h"

#define BUFFER_SIZE (1024 * 8)

enum {
	HTTPMessageIncomplete = 1 << 0,
	HTTPKeepAlive = 1 << 1,
};

static http_parser_settings const settings;

struct HTTPConnection {
	SocketRef socket;
	http_parser parser[1];
	HTTPEvent type;
	uv_buf_t out[1];
	unsigned flags;

	// For logging.
	uint16_t res_status;
	uint64_t res_length;
};

int HTTPConnectionCreateIncoming(uv_stream_t *const ssocket, unsigned const flags, HTTPConnectionRef *const out) {
	return HTTPConnectionCreateIncomingSecure(ssocket, NULL, flags, out);
}
int HTTPConnectionCreateIncomingSecure(uv_stream_t *const ssocket, struct tls *const ssecure, unsigned const flags, HTTPConnectionRef *const out) {
	HTTPConnectionRef conn = calloc(1, sizeof(struct HTTPConnection));
	if(!conn) return UV_ENOMEM;
	int rc = SocketAccept(ssocket, ssecure, &conn->socket);
	if(rc < 0) goto cleanup;

	http_parser_init(conn->parser, HTTP_REQUEST);
	conn->parser->data = conn;
	conn->res_status = 0;
	conn->res_length = UINT64_MAX;

	*out = conn; conn = NULL;
cleanup:
	HTTPConnectionFree(&conn);
	return rc;
}

int HTTPConnectionCreateOutgoing(char const *const domain, unsigned const flags, HTTPConnectionRef *const out) {
	return HTTPConnectionCreateOutgoingSecure(domain, flags, NULL, out);
}
int HTTPConnectionCreateOutgoingSecure(char const *const domain, unsigned const flags, struct tls_config *const tlsconf, HTTPConnectionRef *const out) {
	char host[1023+1]; host[0] = '\0';
	char service[15+1]; service[0] = '\0';
	int matched = sscanf(domain, "%1023[^:]:%15[0-9]", host, service);
	if(matched < 1) return UV_EINVAL;
	if('\0' == host[0]) return UV_EINVAL;

	HTTPConnectionRef conn = calloc(1, sizeof(struct HTTPConnection));
	if(!conn) return UV_ENOMEM;
	int rc;

	if('\0' == service[0]) {
		rc = strlcpy(service, tlsconf ? "443" : "80", sizeof(service));
		if(rc < 0) goto cleanup;
		assert(rc < sizeof(service));
	}
	rc = SocketConnect(host, service, tlsconf, &conn->socket);
	if(rc < 0) goto cleanup;

	http_parser_init(conn->parser, HTTP_RESPONSE);
	conn->parser->data = conn;
	conn->flags |= HTTPKeepAlive;
	conn->res_status = 0;
	conn->res_length = UINT64_MAX;

	*out = conn; conn = NULL;
cleanup:
	HTTPConnectionFree(&conn);
	return rc;
}
void HTTPConnectionFree(HTTPConnectionRef *const connptr) {
	HTTPConnectionRef conn = *connptr; *connptr = NULL;
	if(!conn) return;

	SocketFree(&conn->socket);

	// http_parser does not need to be freed, closed or destroyed.
	memset(conn->parser, 0, sizeof(*conn->parser));

	conn->type = HTTPNothing;
	*conn->out = uv_buf_init(NULL, 0);

	conn->flags = 0;

	conn->res_status = 0;
	conn->res_length = 0;

	assert_zeroed(conn, 1);
	FREE(&conn);
}

void HTTPConnectionSetKeepAlive(HTTPConnectionRef const conn, bool const flag) {
	if(!conn) return;
	if(flag) conn->flags |= HTTPKeepAlive;
	else conn->flags &= ~HTTPKeepAlive;
}

int HTTPConnectionStatus(HTTPConnectionRef const conn) {
	if(!conn) return UV_EINVAL;
	int rc = HTTP_PARSER_ERRNO(conn->parser);
	if(HPE_INVALID_EOF_STATE == rc) return UV_ECONNABORTED;
	if(HPE_OK != rc && HPE_PAUSED != rc) return UV_UNKNOWN;
	rc = SocketStatus(conn->socket);
	if(rc < 0) return rc;
	return 0;
}
int HTTPConnectionPeek(HTTPConnectionRef const conn, HTTPEvent *const type, uv_buf_t *const buf) {
	if(!conn) return UV_EINVAL;
	if(!type) return UV_EINVAL;
	if(!buf) return UV_EINVAL;

	// Repeat previous errors.
	int rc = HTTPConnectionStatus(conn);
	if(rc < 0) return rc;

	while(HTTPNothing == conn->type) {
		uv_buf_t raw[1];
		rc = SocketPeek(conn->socket, raw);
		if(UV_EAGAIN == rc) continue;
		if(UV_EOF == rc && (HTTPMessageIncomplete & conn->flags)) {
			rc = 0;
			*raw = uv_buf_init(NULL, 0);
		}
		if(rc < 0) return rc;

		http_parser_pause(conn->parser, 0);
		size_t len = http_parser_execute(conn->parser, &settings, raw->base, raw->len);
		rc = HTTP_PARSER_ERRNO(conn->parser);

		// HACK: http_parser returns 1 when the input length is 0 (EOF).
		if(len > raw->len) len = raw->len;

		SocketPop(conn->socket, len);

		if(HPE_INVALID_EOF_STATE == rc) return UV_ECONNABORTED;
		if(HPE_OK != rc && HPE_PAUSED != rc) {
			// TODO: We should convert HPE_* and return them
			// instead of logging and returning UV_UNKNOWN.
//			alogf("HTTP parse error: %s (%d)\n",
//				http_errno_name(rc),
//				HTTP_PARSER_ERRNO_LINE(conn->parser));
//			alogf("%s (%lu)\n", strndup(raw->base, raw->len), raw->len);
			return UV_UNKNOWN;
		}
	}
	assertf(HTTPNothing != conn->type, "HTTPConnectionPeek must return an event");
	*type = conn->type;
	*buf = *conn->out;
	return 0;
}
void HTTPConnectionPop(HTTPConnectionRef const conn, size_t const len) {
	if(!conn) return;
	assert(len <= conn->out->len);
	conn->out->base += len;
	conn->out->len -= len;
	if(conn->out->len) return;
	conn->type = HTTPNothing;
	conn->out->base = NULL;
}


ssize_t HTTPConnectionReadRequest(HTTPConnectionRef const conn, HTTPMethod *const method, char *const out, size_t const max) {
	if(!conn) return UV_EINVAL;
	if(!max) return UV_EINVAL;
	uv_buf_t buf[1];
	int rc;
	HTTPEvent type;
	size_t len = 0;
	for(;;) {
		// TODO
		// Use unref because we shouldn't block the server
		// on a request that may never arrive.
//		uv_unref((uv_handle_t *)conn->stream);
		rc = HTTPConnectionPeek(conn, &type, buf);
//		uv_ref((uv_handle_t *)conn->stream);
		if(rc < 0) return rc;
		if(HTTPHeaderField == type || HTTPHeadersComplete == type) break;
		HTTPConnectionPop(conn, buf->len);
		if(HTTPMessageBegin == type) continue;
		if(HTTPURL != type) {
			assertf(0, "Unexpected HTTP event %d", type);
			return UV_UNKNOWN;
		}
		if(len+buf->len+1 > max) return UV_EMSGSIZE;
		memcpy(out+len, buf->base, buf->len);
		len += buf->len;
		out[len] = '\0';
	}
	*method = conn->parser->method;
	return (ssize_t)len;
}
int HTTPConnectionReadResponseStatus(HTTPConnectionRef const conn, int *const status) {
	if(!conn) return UV_EINVAL;
	uv_buf_t buf[1];
	int rc;
	HTTPEvent type;
	for(;;) {
		rc = HTTPConnectionPeek(conn, &type, buf);
		if(rc < 0) return rc;
		if(HTTPHeaderField == type || HTTPHeadersComplete == type) break;
		if(HTTPMessageBegin != type) {
			assertf(0, "Unexpected HTTP event %d", type);
			return UV_UNKNOWN;
		}
		HTTPConnectionPop(conn, buf->len);
	}
	if(status) *status = conn->parser->status_code;
	return 0;
}

ssize_t HTTPConnectionReadHeaderField(HTTPConnectionRef const conn, char out[], size_t const max) {
	if(!conn) return UV_EINVAL;
	uv_buf_t buf[1];
	int rc;
	HTTPEvent type;
	size_t len = 0;
	if(max > 0) out[0] = '\0';
	for(;;) {
		rc = HTTPConnectionPeek(conn, &type, buf);
		if(rc < 0) return rc;
		if(HTTPHeaderValue == type) break;
		if(HTTPHeadersComplete == type) break;
		HTTPConnectionPop(conn, buf->len);
		if(HTTPHeaderField != type) {
			assertf(0, "Unexpected HTTP event %d", type);
			return UV_UNKNOWN;
		}
		if(len+buf->len+1 > max) return UV_EMSGSIZE;
		memcpy(out+len, buf->base, buf->len);
		len += buf->len;
		out[len] = '\0';
	}
	return (ssize_t)len;
}
ssize_t HTTPConnectionReadHeaderValue(HTTPConnectionRef const conn, char out[], size_t const max) {
	if(!conn) return UV_EINVAL;
	uv_buf_t buf[1];
	int rc;
	HTTPEvent type;
	size_t len = 0;
	if(max > 0) out[0] = '\0';
	for(;;) {
		rc = HTTPConnectionPeek(conn, &type, buf);
		if(rc < 0) return rc;
		if(HTTPHeaderField == type) break;
		if(HTTPHeadersComplete == type) break;
		HTTPConnectionPop(conn, buf->len);
		if(HTTPHeaderValue != type) {
			assertf(0, "Unexpected HTTP event %d", type);
			return UV_UNKNOWN;
		}
		if(len+buf->len+1 > max) return UV_EMSGSIZE;
		memcpy(out+len, buf->base, buf->len);
		len += buf->len;
		out[len] = '\0';
	}
	return (ssize_t)len;
}
int HTTPConnectionReadBody(HTTPConnectionRef const conn, uv_buf_t *const buf) {
	if(!conn) return UV_EINVAL;
	HTTPEvent type;
	int rc = HTTPConnectionPeek(conn, &type, buf);
	if(rc < 0) return rc;
	if(HTTPBody != type && HTTPMessageEnd != type) {
		assertf(0, "Unexpected HTTP event %d", type);
		return UV_UNKNOWN;
	}
	HTTPConnectionPop(conn, buf->len);
	return 0;
}

// TODO: Get rid of this.
static size_t append_buf_to_string(char *const dst, size_t const dsize, char const *const src, size_t const slen) {
	if(!dsize) return 0;
	size_t const olen = strlen(dst);
	size_t const nlen = MIN(olen + slen, dsize-1);
	memcpy(dst + olen, src, nlen - olen);
	dst[nlen] = '\0';
	return nlen - olen;
}

int HTTPConnectionReadBodyLine(HTTPConnectionRef const conn, char out[], size_t const max) {
	if(!conn) return UV_EINVAL;
	if(!max) return UV_EINVAL;
	uv_buf_t buf[1];
	int rc;
	size_t i;
	HTTPEvent type;
	out[0] = '\0';
	for(;;) {
		rc = HTTPConnectionPeek(conn, &type, buf);
		if(rc < 0) return rc;
		if(HTTPMessageEnd == type) {
			if(out[0]) return 0;
			HTTPConnectionPop(conn, buf->len);
			return UV_EOF;
		}
		if(HTTPBody != type) {
			assertf(0, "Unexpected HTTP event %d", type);
			return UV_UNKNOWN;
		}
		for(i = 0; i < buf->len; ++i) {
			if('\r' == buf->base[i]) break;
			if('\n' == buf->base[i]) break;
		}
		append_buf_to_string(out, max, buf->base, i);
		HTTPConnectionPop(conn, i);
		if(i < buf->len) break;
	}

	rc = HTTPConnectionPeek(conn, &type, buf);
	if(rc < 0) return rc;
	if(HTTPMessageEnd == type) {
		if(out[0]) return 0;
		HTTPConnectionPop(conn, i);
		return UV_EOF;
	}
	if(HTTPBody != type) return UV_UNKNOWN;
	if('\r' == buf->base[0]) HTTPConnectionPop(conn, 1);

	rc = HTTPConnectionPeek(conn, &type, buf);
	if(rc < 0) return rc;
	if(HTTPMessageEnd == type) {
		if(out[0]) return 0;
		HTTPConnectionPop(conn, i);
		return UV_EOF;
	}
	if(HTTPBody != type) return UV_UNKNOWN;
	if('\n' == buf->base[0]) HTTPConnectionPop(conn, 1);

	return 0;
}
ssize_t HTTPConnectionReadBodyStatic(HTTPConnectionRef const conn, unsigned char *const out, size_t const max) {
	if(!conn) return UV_EINVAL;
	ssize_t len = 0;
	for(;;) {
		uv_buf_t buf[1];
		int rc = HTTPConnectionReadBody(conn, buf);
		if(rc < 0) return rc;
		if(!buf->len) break;
		if(len+buf->len >= max) return UV_EMSGSIZE;
		memcpy(out, buf->base, buf->len);
		len += buf->len;
	}
	return len;
}
int HTTPConnectionDrainMessage(HTTPConnectionRef const conn) {
	if(!conn) return 0;

	// It's critical that we track and report persistent errors here so
	// that the server knows to close the connection. Failure to do so
	// can cause an endless loop as we keep failing to process the same
	// request.
	int rc = HTTPConnectionStatus(conn);
	if(rc < 0) return rc;

	if(!(HTTPMessageIncomplete & conn->flags)) return 0;

	uv_buf_t buf[1];
	HTTPEvent type;
	for(;;) {
		rc = HTTPConnectionPeek(conn, &type, buf);
		if(rc < 0) return rc;
		if(HTTPMessageBegin == type) {
			assertf(0, "HTTPConnectionDrainMessage shouldn't start a new message");
			return UV_UNKNOWN;
		}
		HTTPConnectionPop(conn, buf->len);
		if(HTTPMessageEnd == type) break;
	}
	return 0;
}


int HTTPConnectionWrite(HTTPConnectionRef const conn, unsigned char const *const buf, size_t const len) {
	if(!conn) return 0;
	uv_buf_t info = uv_buf_init((char *)buf, len);
	return SocketWrite(conn->socket, &info);
}
int HTTPConnectionWritev(HTTPConnectionRef const conn, uv_buf_t parts[], unsigned int const count) {
	if(!conn) return 0;
	for(size_t i = 0; i < count; i++) {
		int rc = SocketWrite(conn->socket, &parts[i]);
		if(rc < 0) return rc;
	}
	return 0;
}
int HTTPConnectionWriteRequest(HTTPConnectionRef const conn, HTTPMethod const method, char const *const requestURI, char const *const host) {
	if(!conn) return 0;
	char const *methodstr = http_method_str(method);
	uv_buf_t parts[] = {
		uv_buf_init((char *)methodstr, strlen(methodstr)),
		UV_BUF_STATIC(" "),
		uv_buf_init((char *)requestURI, strlen(requestURI)),
		UV_BUF_STATIC(" HTTP/1.1\r\n"),
		UV_BUF_STATIC("Host: "),
		uv_buf_init((char *)host, strlen(host)),
		UV_BUF_STATIC("\r\n"),
	};
	return HTTPConnectionWritev(conn, parts, numberof(parts));
}

int HTTPConnectionWriteResponse(HTTPConnectionRef const conn, uint16_t const status, char const *const message) {
	assertf(status >= 100 && status < 600, "Invalid HTTP status %d", (int)status);
	if(!conn) return 0;

	conn->res_status = status;

	char status_str[4+1];
	int status_len = snprintf(status_str, sizeof(status_str), "%d", status);
	assert(3 == status_len);

	uv_buf_t parts[] = {
		UV_BUF_STATIC("HTTP/1.1 "),
		uv_buf_init(status_str, status_len),
		UV_BUF_STATIC(" "),
		uv_buf_init((char *)message, strlen(message)),
		UV_BUF_STATIC("\r\n"),
	};
	return HTTPConnectionWritev(conn, parts, numberof(parts));
}
int HTTPConnectionWriteHeader(HTTPConnectionRef const conn, char const *const field, char const *const value) {
	assert(field);
	assert(value);
	if(!conn) return 0;
	uv_buf_t parts[] = {
		uv_buf_init((char *)field, strlen(field)),
		UV_BUF_STATIC(": "),
		uv_buf_init((char *)value, strlen(value)),
		UV_BUF_STATIC("\r\n"),
	};
	return HTTPConnectionWritev(conn, parts, numberof(parts));
}
int HTTPConnectionWriteContentLength(HTTPConnectionRef const conn, uint64_t const length) {
	if(!conn) return 0;

	conn->res_length = length;

	char str[16];
	int const len = snprintf(str, sizeof(str), "%llu", (unsigned long long)length);
	uv_buf_t parts[] = {
		UV_BUF_STATIC("Content-Length: "),
		uv_buf_init(str, len),
		UV_BUF_STATIC("\r\n"),
	};
	return HTTPConnectionWritev(conn, parts, numberof(parts));
}
int HTTPConnectionWriteSetCookie(HTTPConnectionRef const conn, char const *const cookie, char const *const path, uint64_t const maxage) {
	assert(cookie);
	assert(path);
	if(!conn) return 0;
	char maxage_str[16];
	int const maxage_len = snprintf(maxage_str, sizeof(maxage_str), "%llu", (unsigned long long)maxage);
	uv_buf_t parts[] = {
		UV_BUF_STATIC("Set-Cookie: "),
		uv_buf_init((char *)cookie, strlen(cookie)),
		UV_BUF_STATIC("; Path="),
		uv_buf_init((char *)path, strlen(path)),
		UV_BUF_STATIC("; Max-Age="),
		uv_buf_init(maxage_str, maxage_len),
		UV_BUF_STATIC("; HttpOnly"),
		SocketIsSecure(conn->socket) ?
			UV_BUF_STATIC("; Secure" "\r\n") :
			UV_BUF_STATIC("\r\n"),
	};
	return HTTPConnectionWritev(conn, parts, numberof(parts));
}
int HTTPConnectionBeginBody(HTTPConnectionRef const conn) {
	if(!conn) return 0;
	uv_buf_t parts[] = {
		SocketIsSecure(conn->socket) ?
			UV_BUF_STATIC("Strict-Transport-Security: "
				"max-age=31536000; "
				"includeSubDomains; preload" "\r\n") :
			UV_BUF_STATIC(""),
		HTTPKeepAlive & conn->flags ?
			UV_BUF_STATIC("Connection: keep-alive" "\r\n") :
			UV_BUF_STATIC("Connection: close" "\r\n"),
		UV_BUF_STATIC("\r\n"),
	};
	return HTTPConnectionWritev(conn, parts, numberof(parts));
}
int HTTPConnectionWriteFile(HTTPConnectionRef const conn, uv_file const file) {
	// TODO: This function should support lengths and offsets.
	if(!conn) return 0;
	char *buf = malloc(BUFFER_SIZE);
	if(!buf) return UV_ENOMEM;
	uv_buf_t const info = uv_buf_init(buf, BUFFER_SIZE);
	int rc;
	for(;;) {
		ssize_t const len = rc = async_fs_readall_simple(file, &info);
		if(0 == len) break;
		if(rc < 0) break;
		uv_buf_t write = uv_buf_init(buf, len);
		rc = SocketWrite(conn->socket, &write);
		if(rc < 0) break;
	}
	FREE(&buf);
	return rc;
}
int HTTPConnectionWriteChunkLength(HTTPConnectionRef const conn, uint64_t const length) {
	if(!conn) return 0;
	char str[16];
	int const slen = snprintf(str, sizeof(str), "%llx\r\n", (unsigned long long)length);
	if(slen < 0) return UV_UNKNOWN;
	return HTTPConnectionWrite(conn, (unsigned char const *)str, slen);
}
int HTTPConnectionWriteChunkv(HTTPConnectionRef const conn, uv_buf_t parts[], unsigned int const count) {
	if(!conn) return 0;
	uint64_t total = 0;
	for(size_t i = 0; i < count; i++) total += parts[i].len;
	if(total <= 0) return 0;
	int rc = 0;
	rc = rc < 0 ? rc : HTTPConnectionWriteChunkLength(conn, total);
	rc = rc < 0 ? rc : HTTPConnectionWritev(conn, parts, count);
	rc = rc < 0 ? rc : HTTPConnectionWrite(conn, (unsigned char const *)STR_LEN("\r\n"));
	return rc;
}
int HTTPConnectionWriteChunkFile(HTTPConnectionRef const conn, char const *const path) {
	bool worker = false;
	uv_file file = -1;
	unsigned char *buf = NULL;
	int rc;

	async_pool_enter(NULL); worker = true;
	rc = async_fs_open(path, O_RDONLY, 0000);
	if(rc < 0) goto cleanup;
	file = rc;

	buf = malloc(BUFFER_SIZE);
	if(!buf) rc = UV_ENOMEM;
	if(rc < 0) goto cleanup;

	uv_buf_t chunk = uv_buf_init((char *)buf, BUFFER_SIZE);
	ssize_t len = async_fs_readall_simple(file, &chunk);
	if(len < 0) rc = len;
	if(rc < 0) goto cleanup;

	// Fast path for small files.
	if(len < BUFFER_SIZE) {
		char pfx[16];
		int const pfxlen = snprintf(pfx, sizeof(pfx), "%llx\r\n", (unsigned long long)len);
		if(pfxlen < 0) rc = UV_UNKNOWN;
		if(rc < 0) goto cleanup;

		uv_buf_t parts[] = {
			uv_buf_init(pfx, pfxlen),
			uv_buf_init((char *)buf, len),
			UV_BUF_STATIC("\r\n"),
		};
		async_fs_close(file); file = -1;
		async_pool_leave(NULL); worker = false;
		rc = HTTPConnectionWritev(conn, parts, numberof(parts));
		goto cleanup;
	}

	uv_fs_t req[1];
	rc = async_fs_fstat(file, req);
	if(rc < 0) goto cleanup;
	if(0 == req->statbuf.st_size) goto cleanup;

	async_pool_leave(NULL); worker = false;

	// TODO: HACK, WriteFile continues from where we left off
	rc = rc < 0 ? rc : HTTPConnectionWriteChunkLength(conn, req->statbuf.st_size);
	rc = rc < 0 ? rc : HTTPConnectionWritev(conn, &chunk, 1);
	rc = rc < 0 ? rc : HTTPConnectionWriteFile(conn, file);
	rc = rc < 0 ? rc : HTTPConnectionWrite(conn, (unsigned char const *)STR_LEN("\r\n"));

cleanup:
	FREE(&buf);
	if(file >= 0) { async_fs_close(file); file = -1; }
	if(worker) { async_pool_leave(NULL); worker = false; }
	assert(file < 0);
	assert(!worker);
	return rc;
}
int HTTPConnectionWriteChunkEnd(HTTPConnectionRef const conn) {
	if(!conn) return 0;
	return HTTPConnectionWrite(conn, (unsigned char const *)STR_LEN("0\r\n\r\n"));
}
int HTTPConnectionEnd(HTTPConnectionRef const conn) {
	if(!conn) return 0;
	int rc = HTTPConnectionFlush(conn);
	if(rc < 0) return rc;
	if(HTTPKeepAlive & conn->flags) return 0;
	SocketClose(conn->socket);
	return 0;
}
int HTTPConnectionFlush(HTTPConnectionRef const conn) {
	if(!conn) return 0;
	return SocketFlush(conn->socket, false);
}

int HTTPConnectionSendMessage(HTTPConnectionRef const conn, uint16_t const status, char const *const str) {
	if(!conn) return 0;
	size_t const len = strlen(str);
	int rc = 0;
	rc = rc < 0 ? rc : HTTPConnectionWriteResponse(conn, status, str);
	rc = rc < 0 ? rc : HTTPConnectionWriteHeader(conn, "Content-Type", "text/plain; charset=utf-8");
	rc = rc < 0 ? rc : HTTPConnectionWriteContentLength(conn, len+1);
	rc = rc < 0 ? rc : HTTPConnectionBeginBody(conn);
	if(HTTP_HEAD != conn->parser->method) {
		rc = rc < 0 ? rc : HTTPConnectionWrite(conn, (unsigned char const *)str, len);
		rc = rc < 0 ? rc : HTTPConnectionWrite(conn, (unsigned char const *)STR_LEN("\n"));
	}
	rc = rc < 0 ? rc : HTTPConnectionEnd(conn);
	return rc;
}
int HTTPConnectionSendStatus(HTTPConnectionRef const conn, uint16_t const status) {
	char const *const str = statusstr(status);
	return HTTPConnectionSendMessage(conn, status, str);
}
int HTTPConnectionSendRedirect(HTTPConnectionRef const conn, uint16_t const status, char const *const location) {
	int rc = 0;
	char const *const str = statusstr(status);
	rc = rc < 0 ? rc : HTTPConnectionWriteResponse(conn, status, str);
	rc = rc < 0 ? rc : HTTPConnectionWriteHeader(conn, "Location", location);
	rc = rc < 0 ? rc : HTTPConnectionWriteContentLength(conn, 0);
	rc = rc < 0 ? rc : HTTPConnectionBeginBody(conn);
	rc = rc < 0 ? rc : HTTPConnectionEnd(conn);
	return rc;
}
int HTTPConnectionSendFile(HTTPConnectionRef const conn, char const *const path, char const *const type, int64_t size) {
	int rc = async_fs_open(path, O_RDONLY, 0000);
	if(UV_ENOENT == rc) return HTTPConnectionSendStatus(conn, 404);
	if(rc < 0) return HTTPConnectionSendStatus(conn, 400); // TODO: Error conversion.

	uv_file file = rc; rc = 0;
	if(size < 0) {
		uv_fs_t req[1];
		rc = async_fs_fstat(file, req);
		if(rc < 0) {
			rc = HTTPConnectionSendStatus(conn, 400);
			goto cleanup;
		}
		if(S_ISDIR(req->statbuf.st_mode)) {
			rc = UV_EISDIR;
			goto cleanup;
		}
		if(!S_ISREG(req->statbuf.st_mode)) {
			rc = HTTPConnectionSendStatus(conn, 403);
			goto cleanup;
		}
		size = req->statbuf.st_size;
	}
	rc = rc < 0 ? rc : HTTPConnectionWriteResponse(conn, 200, "OK");
	rc = rc < 0 ? rc : HTTPConnectionWriteContentLength(conn, size);
	rc = rc < 0 ? rc : HTTPConnectionWriteHeader(conn, "Cache-Control", "max-age=604800, public"); // TODO: Just cache all static files for one week, for now.
	if(type) rc = rc < 0 ? rc : HTTPConnectionWriteHeader(conn, "Content-Type", type);
	rc = rc < 0 ? rc : HTTPConnectionBeginBody(conn);
	if(HTTP_HEAD != conn->parser->method) {
		rc = rc < 0 ? rc : HTTPConnectionWriteFile(conn, file);
	}
	rc = rc < 0 ? rc : HTTPConnectionEnd(conn);

cleanup:
	async_fs_close(file); file = -1;
	return rc;
}


char const *HTTPConnectionGetProtocol(HTTPConnectionRef const conn) {
	if(!conn) return NULL;
	return SocketIsSecure(conn->socket) ? "https" : "http";
}

static void ensafen(char *const out, size_t const max, char const *const str) {
	assert(max >= 31+1);
	if(!str || '\0' == str[0]) return (void)strlcpy(out, "-", max);
	for(size_t i = 0; str[i]; i++) {
		char const x = str[i];
		if(!isalnum(x) && '-' != x && '.' != x && ':' != x) {
			return (void)strlcpy(out, "(unsafe-value)", max);
		}
	}
	strlcpy(out, str, max);
}
static void escapen(char *const out, size_t const max, char const *const str) {
	assert(max >= 31+1);
	if(!str || '\0' == str[0]) return (void)strlcpy(out, "-", max);
	// TODO: Proper escaping.
	if(strchr(str, '"')) return (void)strlcpy(out, "(unsafe value)", max);
	strlcpy(out, str, max);
}
void HTTPConnectionLog(HTTPConnectionRef const conn, char const *const URI, char const *const username, HTTPHeadersRef const headers, FILE *const log) {
	if(!conn) return;
	if(!log) return;
	if(0 == conn->res_status) return; // No response sent.
	assert(URI);
	async_pool_enter(NULL);

	// https://httpd.apache.org/docs/1.3/logs.html
	// http://www.loganalyzer.net/log-analyzer/apache-combined-log.html

	time_t const now = time(NULL);
	struct tm t[1];
	gmtime_r(&now, t); // TODO: Error checking?
	char time[31+1];
	size_t len = strftime(time, sizeof(time), "[%d/%b/%Y:%T %z]", t);
	if(0 == len) strlcpy(time, "-", sizeof(time)); // TODO: "[-]"?

	char peer[255+1];
	int rc = SocketGetPeerInfo(conn->socket, peer, sizeof(peer));
	char peer_escaped[255+1];
	if(rc < 0) {
		strlcpy(peer_escaped, "-", sizeof(peer_escaped));
	} else {
		ensafen(peer_escaped, sizeof(peer_escaped), peer);
	}

	char username_escaped[63+1];
	ensafen(username_escaped, sizeof(username_escaped), username);

	char const *const method = http_method_str(conn->parser->method);

	// TODO: Is this check necessary? Depends on what http_parser will accept.
	char const *const URI_escaped = strchr(URI, '"') ? "/unsafe-path" : URI;

	char contentlength[20+1]; // Maximum is 18446744073709551615.
	if(UINT64_MAX == conn->res_length) {
		strlcpy(contentlength, "-", sizeof(contentlength));
	} else {
		snprintf(contentlength, sizeof(contentlength), "%llu", (unsigned long long)conn->res_length);
	}

	char const *const referer = HTTPHeadersGet(headers, "referer");
	char referer_escaped[1023+1];
	escapen(referer_escaped, sizeof(referer_escaped), referer);

	char const *const useragent = HTTPHeadersGet(headers, "user-agent");
	char useragent_escaped[1023+1];
	escapen(useragent_escaped, sizeof(useragent_escaped), useragent);

	char const *const cookie_escaped = "-"; // Don't log sensitive data.

	fprintf(log, "%s %s %s %s \"%s %s %s\" %u %s \"%s\" \"%s\" \"%s\"\n",
		peer_escaped,
		"-",
		username_escaped,
		time,
		method,
		URI_escaped,
		"HTTP/1.1", // http_parser doesn't seem to report this.
		conn->res_status,
		contentlength,
		referer_escaped,
		useragent_escaped,
		cookie_escaped
	);
	async_pool_leave(NULL);
}


static int on_message_begin(http_parser *const parser) {
	HTTPConnectionRef const conn = parser->data;
	assert(!(HTTPMessageIncomplete & conn->flags));
	conn->type = HTTPMessageBegin;
	*conn->out = uv_buf_init(NULL, 0);
	conn->flags |= HTTPMessageIncomplete;
	http_parser_pause(parser, 1);
	return 0;
}
static int on_url(http_parser *const parser, char const *const at, size_t const len) {
	HTTPConnectionRef const conn = parser->data;
	conn->type = HTTPURL;
	*conn->out = uv_buf_init((char *)at, len);
	http_parser_pause(parser, 1);
	return 0;
}
static int on_header_field(http_parser *const parser, char const *const at, size_t const len) {
	HTTPConnectionRef const conn = parser->data;
	conn->type = HTTPHeaderField;
	*conn->out = uv_buf_init((char *)at, len);
	http_parser_pause(parser, 1);
	return 0;
}
static int on_header_value(http_parser *const parser, char const *const at, size_t const len) {
	HTTPConnectionRef const conn = parser->data;
	conn->type = HTTPHeaderValue;
	*conn->out = uv_buf_init((char *)at, len);
	http_parser_pause(parser, 1);
	return 0;
}
static int on_headers_complete(http_parser *const parser) {
	HTTPConnectionRef const conn = parser->data;
	conn->type = HTTPHeadersComplete;
	*conn->out = uv_buf_init(NULL, 0);
	http_parser_pause(parser, 1);
	return 0;
}
static int on_body(http_parser *const parser, char const *const at, size_t const len) {
	HTTPConnectionRef const conn = parser->data;
	conn->type = HTTPBody;
	*conn->out = uv_buf_init((char *)at, len);
	http_parser_pause(parser, 1);
	return 0;
}
static int on_message_complete(http_parser *const parser) {
	HTTPConnectionRef const conn = parser->data;
	assert(HTTPMessageIncomplete & conn->flags);
	conn->type = HTTPMessageEnd;
	*conn->out = uv_buf_init(NULL, 0);
	conn->flags &= ~HTTPMessageIncomplete;

	// Don't wait for a message to begin to clear these.
	// They need to be cleared if we disconnect between messages too.
	// In theory this might clear a response that has already been written,
	// but in practice no one responds and then keeps reading.
	conn->res_status = 0;
	conn->res_length = UINT64_MAX;

	http_parser_pause(parser, 1);
	return 0;
}
static http_parser_settings const settings = {
	.on_message_begin = on_message_begin,
	.on_url = on_url,
	.on_header_field = on_header_field,
	.on_header_value = on_header_value,
	.on_headers_complete = on_headers_complete,
	.on_body = on_body,
	.on_message_complete = on_message_complete,
};

