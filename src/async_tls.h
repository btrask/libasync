// Copyright 2015-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#include <stdbool.h>
#include "async.h"

// https://wiki.mozilla.org/Security/Server_Side_TLS
// https://wiki.mozilla.org/index.php?title=Security/Server_Side_TLS&oldid=1080944
// "Modern" compatibility ciphersuite
#define ASYNC_TLS_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"

// According to SSL Labs, enabling TLS1.1 doesn't do any good...
// Not 100% sure about its status in IE11 though.
#define ASYNC_TLS_PROTOCOLS (TLS_PROTOCOL_TLSv1_2)

typedef struct {
	uv_tcp_t stream[1];
	void *secure;
} async_tls_t;

int async_tls_accept(async_tls_t *const server, async_tls_t *const socket);
int async_tls_connect(char const *const host, char const *const port, bool const secure, async_tls_t *const socket);
void async_tls_close(async_tls_t *const socket);
bool async_tls_is_secure(async_tls_t *const socket);
char const *async_tls_error(async_tls_t  *const socket);

ssize_t async_tls_read(async_tls_t *const socket, unsigned char *const buf, size_t const max);
ssize_t async_tls_write(async_tls_t *const socket, unsigned char const *const buf, size_t const len);

