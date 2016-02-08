
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_contentby.h"
#include "ngx_stream_lua_util.h"
#include "ngx_stream_lua_cache.h"


ngx_int_t
ngx_stream_lua_content_handler_file(ngx_stream_session_t *s)
{
    lua_State                       *L;
    ngx_int_t                        rc;
    u_char                          *script_path;
    ngx_stream_lua_srv_conf_t       *lscf;

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_lua_module);

    script_path = ngx_stream_lua_rebase_path(s->connection->pool,
                                             lscf->content_src.data,
                                             lscf->content_src.len);

    if (script_path == NULL) {
        return NGX_ERROR;
    }

    L = ngx_stream_lua_get_lua_vm(s, NULL);

    /*  load Lua script file (w/ cache)        sp = 1 */
    rc = ngx_stream_lua_cache_loadfile(s->connection->log, L, script_path,
                                       lscf->content_src_key);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /*  make sure we have a valid code chunk */
    ngx_stream_lua_assert(lua_isfunction(L, -1));

    return ngx_stream_lua_content_by_chunk(L, s);
}


ngx_int_t
ngx_stream_lua_content_handler_inline(ngx_stream_session_t *s)
{
    lua_State                       *L;
    ngx_int_t                        rc;
    ngx_stream_lua_srv_conf_t       *lscf;

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_lua_module);

    L = ngx_stream_lua_get_lua_vm(s, NULL);

    /*  load Lua inline script (w/ cache) sp = 1 */
    rc = ngx_stream_lua_cache_loadbuffer(s->connection->log, L,
                                         lscf->content_src.data,
                                         lscf->content_src.len,
                                         lscf->content_src_key,
                                         (const char *)
                                         lscf->content_chunkname);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_stream_lua_content_by_chunk(L, s);
}


ngx_int_t
ngx_stream_lua_content_by_chunk(lua_State *L, ngx_stream_session_t *s)
{
    int                          co_ref;
    ngx_int_t                    rc;
    lua_State                   *co;
    ngx_connection_t            *c;
    ngx_stream_lua_ctx_t        *ctx;
    ngx_stream_lua_cleanup_t    *cln;

    ngx_stream_lua_srv_conf_t      *lscf;

    dd("content by chunk");

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);

    if (ctx == NULL) {
        ctx = ngx_stream_lua_create_ctx(s);
        if (ctx == NULL) {
            return NGX_ERROR;
        }

    } else {
        dd("reset ctx");
        ngx_stream_lua_reset_ctx(s, L, ctx);
    }

    ctx->entered_content_phase = 1;

    /*  {{{ new coroutine to handle session */
    co = ngx_stream_lua_new_thread(s, L, &co_ref);

    if (co == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "stream lua: failed to create new coroutine to "
                      "handle session");

        return NGX_ERROR;
    }

    /*  move code closure to new coroutine */
    lua_xmove(L, co, 1);

    /*  set closure's env table to new coroutine's globals table */
    ngx_stream_lua_get_globals_table(co);
    lua_setfenv(co, -2);

    /*  save nginx session in coroutine globals table */
    ngx_stream_lua_set_session(co, s);

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NGX_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    /*  {{{ register session cleanup hooks */
    cln = ngx_stream_lua_cleanup_add(s, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_stream_lua_session_cleanup_handler;
    cln->data = ctx;
    /*  }}} */

    ctx->context = NGX_STREAM_LUA_CONTEXT_CONTENT;

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_lua_module);

    c = s->connection;

    c->read->handler = ngx_stream_lua_session_handler;
    c->write->handler = ngx_stream_lua_session_handler;

    if (lscf->check_client_abort) {
        ctx->read_event_handler = ngx_stream_lua_rd_check_broken_connection;

        if (!c->read->active) {
            if (ngx_add_event(c->read, NGX_READ_EVENT, 0) != NGX_OK) {
                return NGX_ERROR;
            }
        }

    } else {
        ctx->read_event_handler = ngx_stream_lua_block_reading;
    }

    rc = ngx_stream_lua_run_thread(L, s, ctx, 0);

    if (rc == NGX_ERROR || rc >= NGX_OK) {
        return rc;
    }

    if (rc == NGX_AGAIN) {
        return ngx_stream_lua_run_posted_threads(s->connection, L, s, ctx);
    }

    if (rc == NGX_DONE) {
        return ngx_stream_lua_run_posted_threads(s->connection, L, s, ctx);
    }

    return NGX_OK;
}


void
ngx_stream_lua_content_wev_handler(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx)
{
    (void) ctx->resume_handler(s, ctx);
}


void
ngx_stream_lua_content_handler(ngx_stream_session_t *s)
{
    ngx_stream_lua_srv_conf_t       *lscf;
    ngx_stream_lua_ctx_t            *ctx;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream lua content handler fd:%d",
                   (int) s->connection->fd);

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_lua_module);

    if (lscf->content_handler == NULL) {
        dd("no content handler found");
        ngx_stream_lua_finalize_session(s, NGX_DECLINED);
        return;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);

    dd("ctx = %p", ctx);

    if (ctx == NULL) {
        ctx = ngx_stream_lua_create_ctx(s);
        if (ctx == NULL) {
            ngx_stream_lua_finalize_session(s, NGX_ERROR);
            return;
        }
    }

    dd("entered? %d", (int) ctx->entered_content_phase);

    if (ctx->entered_content_phase) {
        dd("calling wev handler");
        ngx_stream_lua_finalize_session(s, ctx->resume_handler(s, ctx));
        return;
    }

    dd("setting entered");

    ctx->entered_content_phase = 1;

    dd("calling content handler");
    ngx_stream_lua_finalize_session(s, lscf->content_handler(s, ctx));
}
