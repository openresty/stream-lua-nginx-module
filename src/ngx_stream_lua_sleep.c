
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/ngx_subsys_lua_sleep.c.tt2
 */


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
static void ngx_stream_lua_sleep_cleanup(void *data);
static ngx_int_t ngx_stream_lua_sleep_resume(ngx_stream_lua_request_t *r);


static int
ngx_stream_lua_ngx_sleep(lua_State *L)
{
    int                          n;
    ngx_int_t                    delay; /* in msec */
    ngx_stream_lua_request_t    *r;

    ngx_stream_lua_ctx_t                *ctx;
    ngx_stream_lua_co_ctx_t             *coctx;

    n = lua_gettop(L);
    if (n != 1) {
        return luaL_error(L, "attempt to pass %d arguments, but accepted 1", n);
    }

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    delay = (ngx_int_t) (luaL_checknumber(L, 1) * 1000);

    if (delay < 0) {
        return luaL_error(L, "invalid sleep duration \"%d\"", delay);
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT

                               | NGX_STREAM_LUA_CONTEXT_PREREAD

                               | NGX_STREAM_LUA_CONTEXT_SSL_CERT
                               | NGX_STREAM_LUA_CONTEXT_TIMER);

    coctx = ctx->cur_co_ctx;
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    ngx_stream_lua_cleanup_pending_operation(coctx);
    coctx->cleanup = ngx_stream_lua_sleep_cleanup;
    coctx->data = r;

    coctx->sleep.handler = ngx_stream_lua_sleep_handler;
    coctx->sleep.data = coctx;
    coctx->sleep.log = r->connection->log;

    if (delay == 0) {
#ifdef HAVE_POSTED_DELAYED_EVENTS_PATCH
        dd("posting 0 sec sleep event to head of delayed queue");

        coctx->sleep.delayed = 1;
        ngx_post_event(&coctx->sleep, &ngx_posted_delayed_events);
#else
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "ngx.sleep(0)"
                      " called without delayed events patch, this will"
                      " hurt performance");
        ngx_add_timer(&coctx->sleep, (ngx_msec_t) delay);
#endif

    } else {
        dd("adding timer with delay %lu ms, r:%p", (unsigned long) delay, r);

        ngx_add_timer(&coctx->sleep, (ngx_msec_t) delay);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua ready to sleep for %d ms", delay);

    return lua_yield(L, 0);
}


void
ngx_stream_lua_sleep_handler(ngx_event_t *ev)
{
#if (NGX_DEBUG)
    ngx_connection_t                *c;
#endif
    ngx_stream_lua_request_t        *r;
    ngx_stream_lua_ctx_t            *ctx;
    ngx_stream_lua_co_ctx_t         *coctx;

    coctx = ev->data;

    r = coctx->data;

#if (NGX_DEBUG)

    c = r->connection;

#endif

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);

    if (ctx == NULL) {
        return;
    }


    coctx->cleanup = NULL;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "stream lua sleep timer expired");

    ctx->cur_co_ctx = coctx;

    if (ctx->entered_content_phase) {
        (void) ngx_stream_lua_sleep_resume(r);

    } else {
        ctx->resume_handler = ngx_stream_lua_sleep_resume;
        ngx_stream_lua_core_run_phases(r);
    }

}


void
ngx_stream_lua_inject_sleep_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_stream_lua_ngx_sleep);
    lua_setfield(L, -2, "sleep");
}


static void
ngx_stream_lua_sleep_cleanup(void *data)
{
    ngx_stream_lua_co_ctx_t                *coctx = data;

    if (coctx->sleep.timer_set) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
                       "lua clean up the timer for pending ngx.sleep");

        ngx_del_timer(&coctx->sleep);
    }

#ifdef HAVE_POSTED_DELAYED_EVENTS_PATCH
    if (coctx->sleep.posted) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ngx_cycle->log, 0,
                       "lua clean up the posted event for pending ngx.sleep");

        ngx_delete_posted_event(&coctx->sleep);
    }
#endif
}


static ngx_int_t
ngx_stream_lua_sleep_resume(ngx_stream_lua_request_t *r)
{
    lua_State                           *vm;
    ngx_connection_t                    *c;
    ngx_int_t                            rc;
    ngx_uint_t                           nreqs;
    ngx_stream_lua_ctx_t                *ctx;

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ctx->resume_handler = ngx_stream_lua_wev_handler;

    c = r->connection;
    vm = ngx_stream_lua_get_lua_vm(r, ctx);
    nreqs = c->requests;

    rc = ngx_stream_lua_run_thread(vm, r, ctx, 0);

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

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
