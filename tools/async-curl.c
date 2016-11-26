// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <async/async.h>
#include <async/http/HTTP.h>
#include <async/http/status.h>

#define USER_AGENT "async-curl (https://github.com/btrask/libasync)"

#define URL_SCHEME_MAX (31+1)
#define URL_SCHEME_FMT "%31[^:]"
#define URL_HOST_MAX (255+1)
#define URL_HOST_FMT "%255[^/]"
#define URL_DOMAIN_MAX (255+1)
#define URL_DOMAIN_FMT "%255[a-zA-Z0-9.-]"
#define URL_PORT_MAX (15+1)
#define URL_PORT_FMT "%15[0-9]"
#define URL_PATH_MAX (1023+1)
#define URL_PATH_FMT "%1023[^?#]"
#define URL_QUERY_MAX (1023+1)
#define URL_QUERY_FMT "%1023[^#]"

enum {
	URL_EINVAL = -EINVAL,
	URL_EPARSE = -15801,
};

typedef struct {
	char scheme[URL_SCHEME_MAX]; // Not including trailing colon
	char host[URL_HOST_MAX]; // Includes port
	char path[URL_PATH_MAX];
	char query[URL_QUERY_MAX];
	// Fragment is stripped
} url_t;
typedef struct {
	char domain[URL_DOMAIN_MAX];
	char port[URL_PORT_MAX];
} host_t;

static void strlower(char *const str) {
	assert(str);
	for(size_t i = 0; '\0' != str[i]; i++) {
		char const c = str[i];
		if(c >= 'A' && c <= 'Z') str[i] += 'a'-'A'; // 0x20
	}
}
int url_parse(char const *const URL, url_t *const out) {
	assert(out);
	if(!URL) return URL_EINVAL;
	out->scheme[0] = '\0';
	out->host[0] = '\0';
	out->path[0] = '\0';
	out->query[0] = '\0';
	if('/' == URL[0] && '/' == URL[1]) {
		// Scheme-relative
		sscanf(URL, "//" URL_HOST_FMT URL_PATH_FMT URL_QUERY_FMT,
			out->host, out->path, out->query);
		if('\0' == out->host[0]) return URL_EPARSE;
	} else if('/' == URL[0]) {
		// Host-relative
		sscanf(URL, URL_PATH_FMT URL_QUERY_FMT,
			out->path, out->query);
		if('/' != out->path[0]) return URL_EPARSE;
	} else {
		// Absolute
		sscanf(URL, URL_SCHEME_FMT "://" URL_HOST_FMT URL_PATH_FMT URL_QUERY_FMT,
			out->scheme, out->host, out->path, out->query);
		if('\0' == out->scheme[0]) return URL_EPARSE;
		if('\0' == out->host[0]) return URL_EPARSE;
	}
	if('\0' != out->path[0] && '/' != out->path[0]) return URL_EPARSE;
	if('\0' != out->query[0] && '?' != out->query[0]) return URL_EPARSE;
	strlower(out->scheme);
	strlower(out->host);
	return 0;
}
int host_parse(char const *const host, host_t *const out) {
	assert(out);
	if(!host) return URL_EINVAL;
	out->domain[0] = '\0';
	out->port[0] = '\0';
	sscanf(host, URL_DOMAIN_FMT ":" URL_PORT_FMT, out->domain, out->port);
	if('\0' == out->domain[0]) return URL_EPARSE;
	return 0;
}

static int send_get(char const *const URL, HTTPConnectionRef *const out) {
	assert(out);
	HTTPConnectionRef conn = NULL;
	url_t obj[1];
	host_t host[1];
	bool secure;
	int rc = 0;

	rc = url_parse(URL, obj);
	if(rc < 0) goto cleanup;
	rc = host_parse(obj->host, host);
	if(rc < 0) goto cleanup;

	if(0 == strcmp(obj->scheme, "http")) {
		secure = false;
	} else if(0 == strcmp(obj->scheme, "https")) {
		secure = true;
	} else {
		rc = UV_EPROTONOSUPPORT;
		goto cleanup;
	}

	if(0 == strcmp("", obj->path)) {
		strlcpy(obj->path, "/", sizeof(obj->path));
	}
	strlcat(obj->path, obj->query, sizeof(obj->path));

	rc = rc < 0 ? rc : HTTPConnectionConnect(host->domain, host->port, secure, 0, &conn);
	rc = rc < 0 ? rc : HTTPConnectionWriteRequest(conn, HTTP_GET, obj->path, obj->host);
	rc = rc < 0 ? rc : HTTPConnectionWriteHeader(conn, "User-Agent", USER_AGENT);
	HTTPConnectionSetKeepAlive(conn, false); // No point.
	rc = rc < 0 ? rc : HTTPConnectionBeginBody(conn);
	rc = rc < 0 ? rc : HTTPConnectionEnd(conn);
	if(rc < 0) goto cleanup;
	*out = conn; conn = NULL;
cleanup:
	HTTPConnectionFree(&conn);
	return rc;
}


void fetch(void *arg) {
	char const *const url = arg;
	HTTPConnectionRef conn = NULL;
	int status = 0;
	int rc = 0;

	fprintf(stderr, "GET %s HTTP/1.1\n", url);
	rc = send_get(url, &conn);
	if(rc < 0) goto cleanup;

	rc = HTTPConnectionReadResponseStatus(conn, &status);
	if(rc < 0) goto cleanup;
	fprintf(stderr, "HTTP/x.x %d %s\n", status, statusstr(status));

	for(;;) {
		uv_buf_t buf[1];
		HTTPEvent type;
		char field[63+1];
		char value[2047+1];
		rc = HTTPConnectionPeek(conn, &type, buf);
		if(rc < 0) goto cleanup;
		if(HTTPHeadersComplete == type) {
			HTTPConnectionPop(conn, buf->len);
			break;
		}
		rc = HTTPConnectionReadHeaderField(conn, field, sizeof(field));
		if(rc < 0) goto cleanup;
		rc = HTTPConnectionReadHeaderValue(conn, value, sizeof(value));
		if(rc < 0) goto cleanup;
		fprintf(stderr, "%s: %s\n", field, value);
	}
	fprintf(stderr, "\n");

	for(;;) {
		uv_buf_t buf[1];
		rc = HTTPConnectionReadBody(conn, buf);
		if(UV_EOF == rc) break;
		if(rc < 0) goto cleanup;
		fwrite(buf->base, 1, buf->len, stdout);
	}
	rc = 0;

cleanup:
	HTTPConnectionFree(&conn);
	if(rc < 0) {
		fprintf(stderr, "Connection error %s\n", uv_strerror(rc));
		exit(1);
	}
}
int main(int const argc, char *const argv[]) {
	int rc = async_process_init();
	if(rc < 0) abort();

	if(argc <= 1) {
		fprintf(stderr, "Usage: async-curl url\n");
		return 1;
	}
	async_spawn(STACK_DEFAULT, fetch, argv[1]);
	uv_run(async_loop, UV_RUN_DEFAULT);

	return 0;
}

