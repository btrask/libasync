// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "HTTP.h"
#include "../util/common.h"

// HTTPHeaders currently uses linear search of the header fields during
// lookup. The theory is that the total field size is quite small and
// headers are not accessed too often per request, so this might actually
// be faster than a hash table. That said, no micro-benchmarks have been
// done. (If you want to compare, please include the cost of creating
// the hash table.)

// The miserly constraints below are intended to resist
// abuse (i.e. denial of service) as much as possible.

// GitHub serves 21-23 headers in my tests.
#define HEADERS_MAX 25
// Requests: Chrome (99), Firefox (79)
// Responses: GitHub (~300)
#define FIELDS_SIZE (64*5)
// "Strict-Transport-Security" is 25+1.
#define FIELD_MAX (25+1)
// VALUE_MAX should be modestly longer than URI_MAX
// in order to handle the Referer.
#define VALUE_MAX (1023+256+1)
// GitHub only sends ~1800 bytes.
// But remember a long referer counts against this too.
#define TOTAL_MAX (1024*3)

struct HTTPHeaders {
	char *fields;
	char *values[HEADERS_MAX];
	uint16_t count;
	uint16_t offset;
	size_t total;
};

int HTTPHeadersCreate(HTTPHeadersRef *const out) {
	HTTPHeadersRef h = calloc(1, sizeof(struct HTTPHeaders));
	if(!h) return UV_ENOMEM;
	h->fields = calloc(FIELDS_SIZE, 1);
	if(!h->fields) {
		HTTPHeadersFree(&h);
		return UV_ENOMEM;
	}
	h->count = 0;
	h->offset = 0;
	*out = h; h = NULL;
	return 0;
}
int HTTPHeadersCreateFromConnection(HTTPConnectionRef const conn, HTTPHeadersRef *const out) {
	assert(conn);
	int rc = HTTPHeadersCreate(out);
	if(rc < 0) return rc;
	rc = HTTPHeadersLoad(*out, conn);
	if(rc < 0) {
		HTTPHeadersFree(out);
		return rc;
	}
	return 0;
}
void HTTPHeadersFree(HTTPHeadersRef *const hptr) {
	HTTPHeadersRef h = *hptr; *hptr = NULL;
	if(!h) return;
	FREE(&h->fields);
	for(uint16_t i = 0; i < h->count; i++) FREE(&h->values[i]);
	h->count = 0;
	h->offset = 0;
	h->total = 0;
	assert_zeroed(h, 1);
	FREE(&h);
}
int HTTPHeadersLoad(HTTPHeadersRef const h, HTTPConnectionRef const conn) {
	if(!h) return 0;
	if(!conn) return UV_EINVAL;
	uv_buf_t buf[1];
	HTTPEvent type;
	char field[FIELD_MAX];
	char value[VALUE_MAX];
	bool connheader = false;
	int rc;
	for(;;) {
		rc = HTTPConnectionPeek(conn, &type, buf);
		if(rc < 0) return rc;
		if(HTTPHeadersComplete == type) {
			HTTPConnectionPop(conn, buf->len);
			break;
		}
		ssize_t const flen = HTTPConnectionReadHeaderField(conn, field, sizeof(field));
		ssize_t const vlen = HTTPConnectionReadHeaderValue(conn, value, sizeof(value));
		if(UV_ENAMETOOLONG == flen) continue;
		if(flen < 0) return flen;
		if(UV_ENAMETOOLONG == vlen) continue;
		if(vlen < 0) return vlen;

		if(!connheader && 0 == strcasecmp("connection", field)) {
			if(0 == strcasecmp("keep-alive", value)) {
				HTTPConnectionSetKeepAlive(conn, true);
			}
			connheader = true;
		}

		if(h->count >= HEADERS_MAX) continue;
		if(h->offset+flen+1 > FIELDS_SIZE) continue;
		if(h->total+vlen > TOTAL_MAX) continue;
		if(!flen) continue;

		// We could use strlcpy() here, but it doesn't buy us much...
		memcpy(h->fields + h->offset, field, flen+1);
		h->offset += flen+1;
		h->values[h->count] = strndup(value, vlen);
		h->count++;
		h->total += vlen+1;
	}
	return 0;
}
char const *HTTPHeadersGet(HTTPHeadersRef const h, char const *const field) {
	if(!h) return NULL;
	if(!field) return NULL;
	assert(strlen(field)+1 <= FIELD_MAX);
	uint16_t pos = 0;
	for(uint16_t i = 0; i < h->count; i++) {
		// If it mattered, more performance could probably be won by
		// normalizing case ahead of time and using memcmp. But I
		// seriously doubt we care.
		if(0 == strcasecmp(h->fields+pos, field)) {
			return h->values[i];
		}
		pos += strlen(h->fields+pos)+1;
	}
	return NULL;
}

