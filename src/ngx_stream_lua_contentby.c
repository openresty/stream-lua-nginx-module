
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_contentby.h"
#include "ngx_stream_lua_util.h"
#include "ngx_stream_lua_exception.h"
#include "ngx_stream_lua_cache.h"
#include "ngx_stream_lua_probe.h"




ngx_int_t
ngx_stream_lua_content_by_chunk(lua_State *L, ngx_stream_lua_request_t *r)
{
    int                      co_ref;
    ngx_int_t                rc;
    lua_State               *co;
    ngx_event_t             *rev;

    ngx_stream_lua_ctx_t                *ctx;
    ngx_stream_lua_cleanup_t            *cln;
    ngx_stream_lua_loc_conf_t           *llcf;

    dd("content by chunk");

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);

    ngx_stream_lua_assert(ctx != NULL);

    dd("reset ctx");
    ngx_stream_lua_reset_ctx(r, L, ctx);

    ctx->entered_content_phase = 1;

    /*  {{{ new coroutine to handle request */
    co = ngx_stream_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "lua: failed to create new coroutine to handle request");

        return NGX_ERROR;
    }

    /*  move code closure to new coroutine */
    lua_xmove(L, co, 1);

    /*  set closure's env table to new coroutine's globals table */
    ngx_stream_lua_get_globals_table(co);
    lua_setfenv(co, -2);

    /*  save nginx request in coroutine globals table */
    ngx_stream_lua_set_req(co, r);

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NGX_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    /*  {{{ register request cleanup hooks */
    if (ctx->cleanup == NULL) {
        cln = ngx_stream_lua_cleanup_add(r, 0);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_stream_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }
    /*  }}} */

    ctx->context = NGX_STREAM_LUA_CONTEXT_CONTENT;

    llcf = ngx_stream_lua_get_module_loc_conf(r, ngx_stream_lua_module);

    r->connection->read->handler = ngx_stream_lua_request_handler;
    r->connection->write->handler = ngx_stream_lua_request_handler;

    if (llcf->check_client_abort) {
        r->read_event_handler = ngx_stream_lua_rd_check_broken_connection;


        rev = r->connection->read;

        if (!rev->active) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }


    } else {
        r->read_event_handler = ngx_stream_lua_block_reading;
    }

    rc = ngx_stream_lua_run_thread(L, r, ctx, 0);

    if (rc == NGX_ERROR || rc >= NGX_OK) {
        return rc;
    }

    if (rc == NGX_AGAIN) {
        return ngx_stream_lua_content_run_posted_threads(L, r, ctx, 0);
    }

    if (rc == NGX_DONE) {
        return ngx_stream_lua_content_run_posted_threads(L, r, ctx, 1);
    }

    return NGX_OK;
}


void
ngx_stream_lua_content_wev_handler(ngx_stream_lua_request_t *r)
{
    ngx_stream_lua_ctx_t                *ctx;

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "lua ngx_stream_lua_content_wev_handler");

    (void) ctx->resume_handler(r);
}


void
ngx_stream_lua_content_handler(ngx_stream_session_t *s)
{
    ngx_stream_lua_srv_conf_t     *lscf;
    ngx_stream_lua_ctx_t          *ctx;
    ngx_int_t                      rc;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream lua content handler");

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_lua_module);

    if (lscf->content_handler == NULL) {
        dd("no content handler found");
        ngx_stream_finalize_session(s, NGX_DECLINED);

        return;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ctx = ngx_stream_lua_create_ctx(s);
        if (ctx == NULL) {
            ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    dd("entered? %d", (int) ctx->entered_content_phase);

    if (ctx->entered_content_phase) {
        dd("calling wev handler");
        rc = ctx->resume_handler(ctx->request);
        dd("wev handler returns %d", (int) rc);

        ngx_stream_lua_finalize_request(ctx->request, rc);
        return;
    }

    dd("setting entered");

    ctx->entered_content_phase = 1;

    dd("calling content handler");
    ngx_stream_lua_finalize_request(ctx->request,
                                    lscf->content_handler(ctx->request));

    return;
}




ngx_int_t
ngx_stream_lua_content_handler_file(ngx_stream_lua_request_t *r)
{
    lua_State                       *L;
    ngx_int_t                        rc;
    u_char                          *script_path;
    ngx_str_t                        eval_src;

    ngx_stream_lua_loc_conf_t               *llcf;

    llcf = ngx_stream_lua_get_module_loc_conf(r, ngx_stream_lua_module);

    if (ngx_stream_complex_value(r->session, &llcf->content_src, &eval_src)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    script_path = ngx_stream_lua_rebase_path(r->pool, eval_src.data,
                                             eval_src.len);

    if (script_path == NULL) {
        return NGX_ERROR;
    }

    L = ngx_stream_lua_get_lua_vm(r, NULL);

    /*  load Lua script file (w/ cache)        sp = 1 */
    rc = ngx_stream_lua_cache_loadfile(r->connection->log, L, script_path,
                                       llcf->content_src_key);
    if (rc != NGX_OK) {

        return rc;
    }

    /*  make sure we have a valid code chunk */
    ngx_stream_lua_assert(lua_isfunction(L, -1));

    return ngx_stream_lua_content_by_chunk(L, r);
}


ngx_int_t
ngx_stream_lua_content_handler_inline(ngx_stream_lua_request_t *r)
{
    lua_State                   *L;
    ngx_int_t                    rc;

    ngx_stream_lua_loc_conf_t           *llcf;

    llcf = ngx_stream_lua_get_module_loc_conf(r, ngx_stream_lua_module);

    L = ngx_stream_lua_get_lua_vm(r, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = ngx_stream_lua_cache_loadbuffer(r->connection->log, L,
                                         llcf->content_src.value.data,
                                         llcf->content_src.value.len,
                                         llcf->content_src_key,
                                         (const char *)
                                         llcf->content_chunkname);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_stream_lua_content_by_chunk(L, r);
}


ngx_int_t
ngx_stream_lua_content_run_posted_threads(lua_State *L,
    ngx_stream_lua_request_t *r, ngx_stream_lua_ctx_t *ctx, int n)
{
    ngx_int_t                        rc;

    ngx_stream_lua_posted_thread_t          *pt;

    dd("run posted threads: %p", ctx->posted_threads);

    for ( ;; ) {
        pt = ctx->posted_threads;
        if (pt == NULL) {
            goto done;
        }

        ctx->posted_threads = pt->next;

        ngx_stream_lua_probe_run_posted_thread(r, pt->co_ctx->co,
                                               (int) pt->co_ctx->co_status);

        dd("posted thread status: %d", pt->co_ctx->co_status);

        if (pt->co_ctx->co_status != NGX_STREAM_LUA_CO_RUNNING) {
            continue;
        }

        ctx->cur_co_ctx = pt->co_ctx;

        rc = ngx_stream_lua_run_thread(L, r, ctx, 0);

        if (rc == NGX_AGAIN) {
            continue;
        }

        if (rc == NGX_DONE) {
            n++;
            continue;
        }

        if (rc == NGX_OK) {
            while (n > 0) {
                ngx_stream_lua_finalize_request(r, NGX_DONE);
                n--;
            }

            return NGX_OK;
        }

        /* rc == NGX_ERROR || rc > NGX_OK */

        return rc;
    }

done:

    if (n == 1) {
        return NGX_DONE;
    }

    if (n == 0) {
        return NGX_DONE;
    }

    /* n > 1 */

    do {
        ngx_stream_lua_finalize_request(r, NGX_DONE);
    } while (--n > 1);

    return NGX_DONE;
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
