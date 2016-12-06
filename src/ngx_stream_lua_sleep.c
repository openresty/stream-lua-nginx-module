
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_util.h"
#include "ngx_stream_lua_sleep.h"
#include "ngx_stream_lua_contentby.h"


static int ngx_stream_lua_ngx_sleep(lua_State *L);
static void ngx_stream_lua_sleep_handler(ngx_event_t *ev);
static void ngx_stream_lua_sleep_cleanup(ngx_stream_lua_co_ctx_t *coctx);
static ngx_int_t ngx_stream_lua_sleep_resume(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx);


static int
ngx_stream_lua_ngx_sleep(lua_State *L)
{
    int                          n;
    ngx_int_t                    delay; /* in msec */
    ngx_stream_session_t        *s;
    ngx_stream_lua_ctx_t        *ctx;
    ngx_stream_lua_co_ctx_t     *coctx;

    n = lua_gettop(L);
    if (n != 1) {
        return luaL_error(L, "attempt to pass %d arguments, but accepted 1", n);
    }

    s = ngx_stream_lua_get_session(L);
    if (s == NULL) {
        return luaL_error(L, "no session found");
    }

    delay = (ngx_int_t) (luaL_checknumber(L, 1) * 1000);

    if (delay < 0) {
        return luaL_error(L, "invalid sleep duration \"%d\"", delay);
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no session ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT
                                 | NGX_STREAM_LUA_CONTEXT_TIMER);

    coctx = ctx->cur_co_ctx;
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    ngx_stream_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = ngx_stream_lua_sleep_cleanup;
    coctx->data = s;

    coctx->sleep.handler = ngx_stream_lua_sleep_handler;
    coctx->sleep.data = coctx;
    coctx->sleep.log = s->connection->log;

    dd("adding timer with delay %lu ms", (unsigned long) delay);

    ngx_add_timer(&coctx->sleep, (ngx_msec_t) delay);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream lua ready to sleep for %d ms", delay);

    return lua_yield(L, 0);
}


void
ngx_stream_lua_sleep_handler(ngx_event_t *ev)
{
    ngx_stream_session_t      *s;
    ngx_stream_lua_ctx_t      *ctx;
    ngx_stream_lua_co_ctx_t   *coctx;

    coctx = ev->data;

    s = coctx->data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);

    if (ctx == NULL) {
        return;
    }

    coctx->cleanup = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream lua sleep timer expired");

    ctx->cur_co_ctx = coctx;

    (void) ngx_stream_lua_sleep_resume(s, ctx);
}


void
ngx_stream_lua_inject_sleep_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_stream_lua_ngx_sleep);
    lua_setfield(L, -2, "sleep");
}


static void
ngx_stream_lua_sleep_cleanup(ngx_stream_lua_co_ctx_t *coctx)
{
    if (coctx->sleep.timer_set) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
                       "stream lua clean up the timer for pending ngx.sleep");

        ngx_del_timer(&coctx->sleep);
    }
}


static ngx_int_t
ngx_stream_lua_sleep_resume(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx)
{
    lua_State                   *vm;
    ngx_connection_t            *c;
    ngx_int_t                    rc;

    ctx->resume_handler = ngx_stream_lua_wev_handler;

    c = s->connection;
    vm = ngx_stream_lua_get_lua_vm(s, ctx);

    rc = ngx_stream_lua_run_thread(vm, s, ctx, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return ngx_stream_lua_run_posted_threads(c, vm, s, ctx);
    }

    if (rc == NGX_DONE) {
        ngx_stream_lua_finalize_session(s, NGX_DONE);
        return ngx_stream_lua_run_posted_threads(c, vm, s, ctx);
    }

    if (ctx->entered_content_phase) {
        ngx_stream_lua_finalize_session(s, rc);
        return NGX_DONE;
    }

    return rc;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
