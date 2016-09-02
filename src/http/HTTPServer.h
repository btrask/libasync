// Copyright 2014-2016 Ben Trask
// MIT licensed (see LICENSE for details)

#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include "HTTP.h"

typedef struct HTTPServer* HTTPServerRef;

typedef void (*HTTPListener)(void *const context, HTTPServerRef const server, HTTPConnectionRef const conn);

int HTTPServerCreate(HTTPListener const listener, void *const context, HTTPServerRef *const out);
void HTTPServerFree(HTTPServerRef *const serverptr);
int HTTPServerListen(HTTPServerRef const server, char const *const address, int const port);
int HTTPServerListenSecurePaths(HTTPServerRef const server, char const *const address, int const port, char const *const keypath, char const *const crtpath);
void HTTPServerClose(HTTPServerRef const server);

#endif
