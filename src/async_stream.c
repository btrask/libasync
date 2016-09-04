// Copyright 2014-2015 Ben Trask
// MIT licensed (see LICENSE for details)

#include <assert.h>
#include <stdlib.h>
#include <string.h> /* DEBUG */
#include "async.h"

typedef struct {
	async_t *thread;
	ssize_t status;
	unsigned char *buf;
	size_t max;
} async_state;

static void alloc_cb(uv_handle_t *const handle, size_t const suggested_size, uv_buf_t *const buf) {
	async_state *const state = handle->data;
	assert(buf);
	assert(state);
	buf->base = (char *)state->buf;
	buf->len = state->max;
}
static void read_cb(uv_stream_t *const stream, ssize_t const nread, uv_buf_t const *const buf) {
	async_state *const state = stream->data;
	assert(state);
	assert(state->thread);
	state->status = nread ? nread : UV_EAGAIN;
	async_switch(state->thread);
}
ssize_t async_read(uv_stream_t *const stream, unsigned char *const buf, size_t const max) {
	if(!stream) return UV_EINVAL;
	async_state state[1];
	state->thread = async_active();
	state->status = 0;
	state->buf = buf;
	state->max = max;
	stream->data = &state;
	int rc;
	do {
		rc = uv_read_start(stream, alloc_cb, read_cb);
		if(rc < 0) return rc;
		rc = async_yield_cancelable();
		uv_read_stop(stream);
		if(rc < 0) return rc;
		rc = state->status;
	} while(UV_EAGAIN == rc);
	if(UV_EOF == rc) return 0;
	return rc;
}

static void write_cb(uv_write_t *const req, int const status) {
	async_state *const state = req->data;
	assert(state);
	assert(state->thread);
	state->status = status;
	async_switch(state->thread);
}
ssize_t async_write(uv_stream_t *const stream, unsigned char const *const buf, size_t const len) {
	async_state state[1];
	state->thread = async_active();
	uv_write_t req[1];
	req->data = &state;
	uv_buf_t obj = uv_buf_init((char *)buf, len);
	int rc;
	do {
		rc = uv_write(req, stream, &obj, 1, write_cb);
		if(rc < 0) return rc;
		async_yield();
		rc = state->status;
	} while(UV_EAGAIN == rc);
	return rc;
}


static void connect_cb(uv_connect_t *const req, int const status) {
	async_state *const state = req->data;
	state->status = status;
	async_switch(state->thread);
}
int async_tcp_connect(uv_tcp_t *const stream, struct sockaddr const *const addr) {
	async_state state[1];
	state->thread = async_active();
	uv_connect_t req[1];
	req->data = state;
	int rc = uv_tcp_connect(req, stream, addr, connect_cb);
	if(rc < 0) return rc;
	async_yield();
	return state->status;
}


struct poll_state {
	async_t *thread;
	int status;
	int events;
};
static void poll_cb(uv_poll_t *const handle, int const status, int const events) {
	struct poll_state *const state = handle->data;
	state->status = status;
	state->events = events;
	async_switch(state->thread);
}
int async_poll_fd(int const fd, int *const events) {
	assert(events);
	struct poll_state state[1];
	state->thread = async_active();
	state->status = 0;
	state->events = 0;
	uv_poll_t poll[1];
	poll->data = state;
	int rc = uv_poll_init(async_loop, poll, fd);
	if(rc < 0) return rc;
	rc = uv_poll_start(poll, *events, poll_cb);
	if(rc < 0) return rc;
	async_yield();
	async_close((uv_handle_t *)poll);
	*events = state->events;
	return state->status;
}
int async_poll_socket(uv_os_sock_t const socket, int *const events) {
	assert(events);
	struct poll_state state[1];
	state->thread = async_active();
	state->status = 0;
	state->events = 0;
	uv_poll_t poll[1];
	poll->data = state;
	int rc = uv_poll_init_socket(async_loop, poll, socket);
	if(rc < 0) return rc;
	rc = uv_poll_start(poll, *events, poll_cb);
	if(rc < 0) return rc;
	async_yield();
	async_close((uv_handle_t *)poll);
	*events = state->events;
	return state->status;
}

