// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include "../../deps/libressl-portable/include/tls.h"
#include "HTTP.h"

typedef struct HTTPServer* HTTPServerRef;

typedef void (*HTTPListener)(void *const context, HTTPServerRef const server, HTTPConnectionRef const conn);


HTTPServerRef HTTPServerCreate(HTTPListener const listener, void *const context);
void HTTPServerFree(HTTPServerRef *const serverptr);
int HTTPServerListen(HTTPServerRef const server, char const *const address, int const port);
int HTTPServerListenSecure(HTTPServerRef const server, char const *const address, int const port, struct tls **const tlsptr);
void HTTPServerClose(HTTPServerRef const server);

#endif
