// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include "libressl-portable/include/tls.h"
#include "HTTP.h"

// https://wiki.mozilla.org/Security/Server_Side_TLS
// https://wiki.mozilla.org/index.php?title=Security/Server_Side_TLS&oldid=1080944
// "Modern" compatibility ciphersuite
#define TLS_CIPHERS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK"

// According to SSL Labs, enabling TLS1.1 doesn't do any good...
// Not 100% sure about its status in IE11 though.
#define TLS_PROTOCOLS (TLS_PROTOCOL_TLSv1_2)

typedef struct HTTPServer* HTTPServerRef;

typedef void (*HTTPListener)(void *const context, HTTPServerRef const server, HTTPConnectionRef const conn);

int HTTPServerCreate(HTTPListener const listener, void *const context, HTTPServerRef *const out);
void HTTPServerFree(HTTPServerRef *const serverptr);
int HTTPServerListen(HTTPServerRef const server, char const *const address, int const port);
int HTTPServerListenSecure(HTTPServerRef const server, char const *const address, int const port, struct tls **const tlsptr);
void HTTPServerClose(HTTPServerRef const server);

#endif
