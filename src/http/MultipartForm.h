// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#include "HTTP.h"

#define MULTIPART_FIELD_MAX 80

typedef enum {
	MultipartNothing = 0,
	MultipartPartBegin,
	MultipartHeaderField,
	MultipartHeaderValue,
	MultipartHeadersComplete,
	MultipartPartData,
	MultipartPartEnd,
	MultipartFormEnd,
} MultipartEvent;

typedef struct MultipartForm *MultipartFormRef;

int MultipartBoundaryFromType(char const *const type, uv_buf_t *const out);
int MultipartFormCreate(HTTPConnectionRef const conn, uv_buf_t const *const boundary, MultipartFormRef *const out);
void MultipartFormFree(MultipartFormRef *const formptr);

int MultipartFormPeek(MultipartFormRef const form, MultipartEvent *const type, uv_buf_t *const buf);
void MultipartFormPop(MultipartFormRef const form, size_t const len);

int MultipartFormReadHeaderField(MultipartFormRef const form, char field[], size_t const max);
int MultipartFormReadHeaderValue(MultipartFormRef const conn, char value[], size_t const max);
int MultipartFormReadHeadersStatic(MultipartFormRef const form, uv_buf_t values[], char const *const fields[], size_t const count);
int MultipartFormReadData(MultipartFormRef const conn, uv_buf_t *const buf);

