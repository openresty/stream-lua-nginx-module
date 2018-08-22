
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_util.h"


#if (NGX_STREAM_SSL)


int ngx_stream_lua_ssl_ctx_index = -1;


ngx_int_t
ngx_stream_lua_ssl_init(ngx_log_t *log)
{
    if (ngx_stream_lua_ssl_ctx_index == -1) {
        ngx_stream_lua_ssl_ctx_index = SSL_get_ex_new_index(0, NULL,
                                                            NULL,
                                                            NULL,
                                                            NULL);

        if (ngx_stream_lua_ssl_ctx_index == -1) {
            ngx_ssl_error(NGX_LOG_ALERT, log, 0,
                          "lua: SSL_get_ex_new_index() for ctx failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/* Similar to ngx_stream_lua_sleep_resume */
static ngx_int_t
ngx_stream_lua_ssl_handshake_resume(ngx_stream_lua_request_t *r)
{
    lua_State             *vm;
    lua_State             *L;
    ngx_connection_t      *c;
    ngx_int_t              rc;
    ngx_uint_t             nreqs;
    ngx_stream_lua_ctx_t  *ctx;

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->resume_handler = ngx_stream_lua_wev_handler;

    c = r->connection;

    /* push return value */
    L = ctx->cur_co_ctx->co;
    lua_pushboolean(L, c->ssl->handshaked);

    vm = ngx_stream_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = ngx_stream_lua_run_thread(vm, r, ctx, 1);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return ngx_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (rc == NGX_DONE) {
        ngx_stream_lua_finalize_request(r, NGX_DONE);
        return ngx_stream_lua_run_posted_threads(c, vm, r, ctx, nreqs);
    }

    if (ctx->entered_content_phase) {
        ngx_stream_lua_finalize_request(r, rc);
        return NGX_DONE;
    }

    return rc;
}


/* Similar to ngx_stream_ssl_handshake_handler */
static void
ngx_stream_lua_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_stream_session_t      *s;
    ngx_stream_lua_ctx_t      *ctx;
    ngx_stream_lua_request_t  *r;

    s = c->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    r = ctx->request;

    /* XXX: should we stash the one from ngx_stream_lua_req_starttls away for this? */
    ctx->cur_co_ctx = &ctx->entry_co_ctx;

    if (ctx->entered_content_phase) {
        (void) ngx_stream_lua_ssl_handshake_resume(r);

    } else {
        ctx->resume_handler = ngx_stream_lua_ssl_handshake_resume;
        ngx_stream_lua_core_run_phases(r);
    }
}


/* Similar to ngx_stream_ssl_init_connection */
static ngx_int_t
ngx_stream_lua_ssl_init_connection(ngx_connection_t *c,
    SSL_CTX* ptr, ngx_msec_t handshake_timeout)
{
    ngx_int_t                    rc;
    ngx_stream_session_t        *s;
    ngx_stream_core_srv_conf_t  *cscf;
    ngx_ssl_t                   *ssl;
    ngx_pool_cleanup_t          *cln;

    s = c->data;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);

    if (cscf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
        return NGX_ERROR;
    }

    ssl = ngx_pcalloc(c->pool, sizeof(ngx_ssl_t));
    if (ssl == NULL) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    if (!SSL_CTX_up_ref(ptr)) {
        return NGX_ERROR;
    }

    ssl->ctx = ptr;
    ssl->log = c->log;
    ssl->buffer_size = NGX_SSL_BUFSIZE;

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = ssl;

    if (ngx_ssl_create_connection(ssl, c, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->read, handshake_timeout);

        c->ssl->handler = ngx_stream_lua_ssl_handshake_handler;
    }

    return rc;
}


/* Similar to ngx_stream_ssl_init_connection */
int
ngx_stream_lua_req_starttls(lua_State *L)
{
    ngx_stream_lua_request_t  *r;
    ngx_stream_lua_ctx_t      *ctx;
    ngx_stream_lua_co_ctx_t   *coctx;
    ngx_connection_t          *c;
    SSL_CTX                   *ptr;
    ngx_msec_t                 handshake_timeout;
    ngx_int_t                  rc;

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ptr = *(SSL_CTX**)luaL_checkudata(L, 1, "SSL_CTX*");
    handshake_timeout = luaL_optinteger(L, 2, 60000);

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    coctx = ctx->cur_co_ctx;
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    c = r->connection;
    if (c == NULL) {
        return luaL_error(L, "no connection found");
    }

    rc = ngx_stream_lua_ssl_init_connection(c, ptr, handshake_timeout);

    if (rc == NGX_OK) {
        lua_pushboolean(L, 1);
        return 1;
    }

    if (rc == NGX_ERROR) {
        lua_pushboolean(L, 0);
        return 1;
    }

    /* rc == NGX_AGAIN */
    return lua_yield(L, 0);
}


#endif /* NGX_STREAM_SSL */
