#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include "ngx_stream_lua_common.h"
#include "ngx_stream_lua_request.h"


ngx_stream_lua_cleanup_t *
ngx_stream_lua_cleanup_add(ngx_stream_lua_request_t *r, size_t size)
{
    ngx_stream_lua_cleanup_t  *cln;

    cln = ngx_palloc(r->pool, sizeof(ngx_stream_lua_cleanup_t));
    if (cln == NULL) {
        return NULL;
    }

    if (size) {
        cln->data = ngx_palloc(r->pool, size);
        if (cln->data == NULL) {
            return NULL;
        }

    } else {
        cln->data = NULL;
    }

    cln->handler = NULL;
    cln->next = r->cleanup;

    r->cleanup = cln;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "http cleanup add: %p", cln);

    return cln;
}

ngx_stream_lua_request_t *
ngx_stream_lua_create_request(ngx_stream_session_t *s)
{
    ngx_pool_t               *pool;
    ngx_stream_lua_request_t *r;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, s->connection->log);
    if (pool == NULL) {
        return NULL;
    }

    r = ngx_pcalloc(pool, sizeof(ngx_stream_lua_request_t));
    if (r == NULL) {
        return NULL;
    }

    r->connection = s->connection;
    r->session = s;
    r->pool = pool;

    return r;
}

void
ngx_stream_lua_request_handler(ngx_event_t *ev)
{
    ngx_connection_t          *c;
    ngx_stream_session_t      *s;
    ngx_stream_lua_request_t  *r;
    ngx_stream_lua_ctx_t      *ctx;

    c = ev->data;
    s = c->data;

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);
    if (ctx == NULL) {
        return;
    }

    r = ctx->request;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "session run request: \"%p\"", r);

    if (ev->write) {
        r->write_event_handler(r);

    } else {
        r->read_event_handler(r);
    }
}

void
ngx_stream_lua_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, wev->log, 0,
                   "stream lua empty handler");
    return;
}

void
ngx_stream_lua_block_reading(ngx_stream_lua_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "stream reading blocked");

    /* aio does not call this handler */

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT)
        && r->connection->read->active)
    {
        if (ngx_del_event(r->connection->read, NGX_READ_EVENT, 0) != NGX_OK) {
            ngx_stream_lua_finalize_real_request(r, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
    }
}

void
ngx_stream_lua_finalize_real_request(ngx_stream_lua_request_t *r, ngx_int_t rc)
{
    ngx_stream_lua_cleanup_t  *cln;
    ngx_pool_t                *pool;
    ngx_stream_session_t      *s;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "finalize stream request: %i", rc);

    s = r->session;

    if (rc == NGX_DONE || rc == NGX_DECLINED) {
        goto cleanup;
    }

    if (rc == NGX_ERROR) {
        rc = NGX_STREAM_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }

cleanup:
    cln = r->cleanup;
    r->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    pool = r->pool;
    r->pool = NULL;

    ngx_destroy_pool(pool);

    ngx_stream_finalize_session(s, NGX_STREAM_OK);
    return;
}
