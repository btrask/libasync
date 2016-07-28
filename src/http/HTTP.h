// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef HTTPCONNECTION_H
#define HTTPCONNECTION_H

#include <stdbool.h>
#include "libressl-portable/include/tls.h"
#include "http_parser/http_parser.h"
#include "../async.h"

typedef enum http_method HTTPMethod;
typedef enum {
	HTTPNothing = 0,
	HTTPMessageBegin,
	HTTPURL,
	HTTPHeaderField,
	HTTPHeaderValue,
	HTTPHeadersComplete,
	HTTPBody,
	HTTPMessageEnd,
} HTTPEvent;

typedef struct HTTPConnection* HTTPConnectionRef;
typedef struct HTTPHeaders* HTTPHeadersRef;

int HTTPConnectionCreateIncoming(uv_stream_t *const ssocket, unsigned const flags, HTTPConnectionRef *const out);
int HTTPConnectionCreateIncomingSecure(uv_stream_t *const ssocket, struct tls *const ssecure, unsigned const flags, HTTPConnectionRef *const out);
int HTTPConnectionCreateOutgoing(char const *const domain, unsigned const flags, HTTPConnectionRef *const out);
int HTTPConnectionCreateOutgoingSecure(char const *const domain, unsigned const flags, struct tls_config *const tlsconf, HTTPConnectionRef *const out);
void HTTPConnectionFree(HTTPConnectionRef *const connptr);

void HTTPConnectionSetKeepAlive(HTTPConnectionRef const conn, bool const flag);

// Reading
int HTTPConnectionStatus(HTTPConnectionRef const conn); // NOT a HTTP status code.
int HTTPConnectionPeek(HTTPConnectionRef const conn, HTTPEvent *const type, uv_buf_t *const buf);
void HTTPConnectionPop(HTTPConnectionRef const conn, size_t const len);

ssize_t HTTPConnectionReadRequest(HTTPConnectionRef const conn, HTTPMethod *const method, char *const out, size_t const max);
int HTTPConnectionReadResponseStatus(HTTPConnectionRef const conn, int *const status);
ssize_t HTTPConnectionReadHeaderField(HTTPConnectionRef const conn, char out[], size_t const max);
ssize_t HTTPConnectionReadHeaderValue(HTTPConnectionRef const conn, char out[], size_t const max);
int HTTPConnectionReadBody(HTTPConnectionRef const conn, uv_buf_t *const buf);
int HTTPConnectionReadBodyLine(HTTPConnectionRef const conn, char out[], size_t const max);
ssize_t HTTPConnectionReadBodyStatic(HTTPConnectionRef const conn, unsigned char *const out, size_t const max);
int HTTPConnectionDrainMessage(HTTPConnectionRef const conn);

// Writing
int HTTPConnectionWrite(HTTPConnectionRef const conn, unsigned char const *const buf, size_t const len);
int HTTPConnectionWritev(HTTPConnectionRef const conn, uv_buf_t parts[], unsigned int const count);
int HTTPConnectionWriteRequest(HTTPConnectionRef const conn, HTTPMethod const method, char const *const requestURI, char const *const host);
int HTTPConnectionWriteResponse(HTTPConnectionRef const conn, uint16_t const status, char const *const message);
int HTTPConnectionWriteHeader(HTTPConnectionRef const conn, char const *const field, char const *const value);
int HTTPConnectionWriteContentLength(HTTPConnectionRef const conn, uint64_t const length);
int HTTPConnectionWriteSetCookie(HTTPConnectionRef const conn, char const *const cookie, char const *const path, uint64_t const maxage);
int HTTPConnectionBeginBody(HTTPConnectionRef const conn);
int HTTPConnectionWriteFile(HTTPConnectionRef const conn, uv_file const file);
int HTTPConnectionWriteChunkLength(HTTPConnectionRef const conn, uint64_t const length);
int HTTPConnectionWriteChunkv(HTTPConnectionRef const conn, uv_buf_t parts[], unsigned int const count);
int HTTPConnectionWriteChunkFile(HTTPConnectionRef const conn, char const *const path);
int HTTPConnectionWriteChunkEnd(HTTPConnectionRef const conn);
int HTTPConnectionEnd(HTTPConnectionRef const conn);
int HTTPConnectionFlush(HTTPConnectionRef const conn);

// Convenience
int HTTPConnectionSendString(HTTPConnectionRef const conn, uint16_t const status, char const *const str);
int HTTPConnectionSendStatus(HTTPConnectionRef const conn, uint16_t const status);
int HTTPConnectionSendRedirect(HTTPConnectionRef const conn, uint16_t const status, char const *const location);
int HTTPConnectionSendSecureRedirect(HTTPConnectionRef const conn, char const *const domain, int const port, char const *const URI); // From HTTP to HTTPS.
int HTTPConnectionSendFile(HTTPConnectionRef const conn, char const *const path, char const *const type, int64_t size);

// Misc
char const *HTTPConnectionGetProtocol(HTTPConnectionRef const conn);
void HTTPConnectionLog(HTTPConnectionRef const conn, char const *const URI, char const *const username, HTTPHeadersRef const headers, FILE *const log);

// Headers
int HTTPHeadersCreate(HTTPHeadersRef *const out);
int HTTPHeadersCreateFromConnection(HTTPConnectionRef const conn, HTTPHeadersRef *const out);
void HTTPHeadersFree(HTTPHeadersRef *const hptr);
int HTTPHeadersLoad(HTTPHeadersRef const h, HTTPConnectionRef const conn);
char const *HTTPHeadersGet(HTTPHeadersRef const h, char const *const field);

#endif // HTTPCONNECTION_H
