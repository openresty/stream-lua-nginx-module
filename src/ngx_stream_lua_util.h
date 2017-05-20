
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 */


#ifndef _NGX_STREAM_LUA_UTIL_H_INCLUDED_
#define _NGX_STREAM_LUA_UTIL_H_INCLUDED_


#include "ngx_stream_lua_common.h"


u_char *ngx_stream_lua_rebase_path(ngx_pool_t *pool, u_char *src, size_t len);
u_char *ngx_stream_lua_digest_hex(u_char *dest, const u_char *buf, int buf_len);
ngx_int_t ngx_stream_lua_wev_handler(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx);
lua_State *ngx_stream_lua_init_vm(lua_State *parent_vm, ngx_cycle_t *cycle,
    ngx_pool_t *pool, ngx_stream_lua_main_conf_t *lmcf, ngx_log_t *log,
    ngx_pool_cleanup_t **pcln);
void ngx_stream_lua_cleanup_vm(void *data);
void ngx_stream_lua_reset_ctx(ngx_stream_session_t *s, lua_State *L,
    ngx_stream_lua_ctx_t *ctx);
lua_State *ngx_stream_lua_new_thread(ngx_stream_session_t *s, lua_State *L,
    int *ref);
void ngx_stream_lua_del_thread(ngx_stream_session_t *s, lua_State *L,
    ngx_stream_lua_ctx_t *ctx, ngx_stream_lua_co_ctx_t *coctx);
void ngx_stream_lua_session_cleanup_handler(void *data);
void ngx_stream_lua_session_cleanup(ngx_stream_lua_ctx_t *ctx, int forcible);
void ngx_stream_lua_finalize_session(ngx_stream_session_t *s, ngx_int_t rc);
void ngx_stream_lua_rd_check_broken_connection(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx);
void ngx_stream_lua_block_reading(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx);
ngx_int_t ngx_stream_lua_run_thread(lua_State *L, ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx, volatile int nrets);
ngx_int_t ngx_stream_lua_run_posted_threads(ngx_connection_t *c, lua_State *L,
    ngx_stream_session_t *s, ngx_stream_lua_ctx_t *ctx);
void ngx_stream_lua_create_new_globals_table(lua_State *L, int narr, int nrec);
void ngx_stream_lua_finalize_fake_session(ngx_stream_session_t *s,
    ngx_int_t rc);
ngx_int_t ngx_stream_lua_check_broken_connection(ngx_stream_session_t *s,
    ngx_event_t *ev);
void ngx_stream_lua_session_handler(ngx_event_t *ev);
void ngx_stream_lua_content_wev_handler(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx);
ngx_int_t ngx_stream_lua_post_thread(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx, ngx_stream_lua_co_ctx_t *coctx);
int ngx_stream_lua_traceback(lua_State *L);
ngx_stream_lua_co_ctx_t *ngx_stream_lua_get_co_ctx(lua_State *L,
    ngx_stream_lua_ctx_t *ctx);
ngx_stream_lua_co_ctx_t *ngx_stream_lua_create_co_ctx(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx);
void ngx_stream_lua_free_fake_session(ngx_stream_session_t *s);
void ngx_stream_lua_close_fake_connection(ngx_connection_t *c);
ngx_stream_lua_cleanup_t *ngx_stream_lua_cleanup_add(ngx_stream_session_t *s,
    size_t size);
void ngx_stream_lua_cleanup_free(ngx_stream_session_t *s,
    ngx_pool_cleanup_pt *cleanup);
ngx_chain_t *ngx_stream_lua_chain_get_free_buf(ngx_log_t *log, ngx_pool_t *p,
    ngx_chain_t **free, size_t len);
uintptr_t ngx_stream_lua_escape_uri(u_char *dst, u_char *src, size_t size,
    ngx_uint_t type);
void ngx_stream_lua_unescape_uri(u_char **dst, u_char **src, size_t size,
    ngx_uint_t type);
ngx_connection_t *ngx_stream_lua_create_fake_connection(ngx_pool_t *pool);
ngx_stream_session_t *ngx_stream_lua_create_fake_session(ngx_connection_t *c);
int ngx_stream_lua_do_call(ngx_log_t *log, lua_State *L);
ngx_int_t ngx_stream_lua_report(ngx_log_t *log, lua_State *L, int status,
    const char *prefix);
void ngx_stream_lua_free_session(ngx_stream_session_t *s);
void ngx_stream_lua_process_args_option(ngx_stream_session_t *s, lua_State *L,
    int table, ngx_str_t *args);
void ngx_stream_lua_set_multi_value_table(lua_State *L, int index);
ngx_addr_t *ngx_stream_lua_parse_addr(lua_State *L, u_char *text, size_t len);


#ifndef NGX_UNESCAPE_URI_COMPONENT
#define NGX_UNESCAPE_URI_COMPONENT  0
#endif


#define ngx_stream_lua_session_key  "__ngx_sess"


#define ngx_stream_lua_context_name(c)                                       \
    ((c) == NGX_STREAM_LUA_CONTEXT_CONTENT ? "content_by_lua*"               \
     : (c) == NGX_STREAM_LUA_CONTEXT_LOG ? "log_by_lua*"                     \
     : (c) == NGX_STREAM_LUA_CONTEXT_TIMER ? "ngx.timer"                     \
     : (c) == NGX_STREAM_LUA_CONTEXT_INIT_WORKER ? "init_worker_by_lua*"     \
     : "(unknown)")


#define ngx_stream_lua_check_context(L, ctx, flags)                          \
    if (!((ctx)->context & (flags))) {                                       \
        return luaL_error(L, "API disabled in the context of %s",            \
                          ngx_stream_lua_context_name((ctx)->context));      \
    }


#define ngx_stream_lua_check_fake_session(L, s)                              \
    if ((s)->connection->fd == (ngx_socket_t) -1) {                          \
        return luaL_error(L, "API disabled in the current context");         \
    }


#define ngx_stream_lua_check_fake_session2(L, r, ctx)                        \
    if ((r)->connection->fd == (ngx_socket_t) -1) {                          \
        return luaL_error(L, "API disabled in the context of %s",            \
                          ngx_stream_lua_context_name((ctx)->context));      \
    }


#ifndef NGX_LUA_NO_FFI_API
static ngx_inline ngx_int_t
ngx_stream_lua_ffi_check_context(ngx_stream_lua_ctx_t *ctx, unsigned flags,
    u_char *err, size_t *errlen)
{
    if (!(ctx->context & flags)) {
        *errlen = ngx_snprintf(err, *errlen,
                               "API disabled in the context of %s",
                               ngx_stream_lua_context_name((ctx)->context))
                  - err;

        return NGX_DECLINED;
    }

    return NGX_OK;
}
#endif


static ngx_inline ngx_stream_session_t *
ngx_stream_lua_get_session(lua_State *L)
{
    ngx_stream_session_t    *s;

    lua_getglobal(L, ngx_stream_lua_session_key);
    s = lua_touserdata(L, -1);
    lua_pop(L, 1);

    return s;
}


static ngx_inline void
ngx_stream_lua_init_ctx(ngx_stream_session_t *s, ngx_stream_lua_ctx_t *ctx)
{
    ngx_connection_t                *c;

    c = s->connection;

    ngx_memzero(ctx, sizeof(ngx_stream_lua_ctx_t));
    ctx->ctx_ref = LUA_NOREF;
    ctx->entry_co_ctx.co_ref = LUA_NOREF;
    ctx->resume_handler = ngx_stream_lua_wev_handler;
    ctx->session = s;

    ctx->out_writer.pool = c->pool;
    ctx->out_writer.last = &ctx->out_writer.out;
    ctx->out_writer.connection = c;
}


static ngx_inline ngx_stream_lua_ctx_t *
ngx_stream_lua_create_ctx(ngx_stream_session_t *s)
{
    lua_State                       *L;
    ngx_pool_cleanup_t              *cln;
    ngx_stream_lua_ctx_t            *ctx;
    ngx_stream_lua_srv_conf_t       *lscf;
    ngx_stream_lua_main_conf_t      *lmcf;

    ctx = ngx_palloc(s->connection->pool, sizeof(ngx_stream_lua_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ngx_stream_lua_init_ctx(s, ctx);
    ngx_stream_set_ctx(s, ctx, ngx_stream_lua_module);

    lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_lua_module);
    if (!lscf->enable_code_cache && s->connection->fd != (ngx_socket_t) -1) {
        lmcf = ngx_stream_get_module_main_conf(s, ngx_stream_lua_module);

        dd("lmcf: %p", lmcf);

        L = ngx_stream_lua_init_vm(lmcf->lua, lmcf->cycle,
                                   s->connection->pool, lmcf,
                                   s->connection->log, &cln);
        if (L == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "failed to initialize Lua VM");
            return NULL;
        }

        if (lmcf->init_handler) {
            if (lmcf->init_handler(s->connection->log, lmcf, L) != NGX_OK) {
                /* an error happened */
                return NULL;
            }
        }

        ctx->vm_state = cln->data;

    } else {
        ctx->vm_state = NULL;
    }

    return ctx;
}


static ngx_inline lua_State *
ngx_stream_lua_get_lua_vm(ngx_stream_session_t *s, ngx_stream_lua_ctx_t *ctx)
{
    ngx_stream_lua_main_conf_t    *lmcf;

    if (ctx == NULL) {
        ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);
    }

    if (ctx && ctx->vm_state) {
        return ctx->vm_state->vm;
    }

    lmcf = ngx_stream_get_module_main_conf(s, ngx_stream_lua_module);
    return lmcf->lua;
}


static ngx_inline void
ngx_stream_lua_get_globals_table(lua_State *L)
{
    lua_pushvalue(L, LUA_GLOBALSINDEX);
}


static ngx_inline void
ngx_stream_lua_set_globals_table(lua_State *L)
{
    lua_replace(L, LUA_GLOBALSINDEX);
}


static ngx_inline void
ngx_stream_lua_set_session(lua_State *L, ngx_stream_session_t *s)
{
    lua_pushlightuserdata(L, s);
    lua_setglobal(L, ngx_stream_lua_session_key);
}


static ngx_inline void
ngx_stream_lua_cleanup_pending_operation(ngx_stream_lua_co_ctx_t *coctx)
{
    if (coctx->cleanup) {
        coctx->cleanup(coctx);
        coctx->cleanup = NULL;
    }
}


/* key in Lua vm registry for all the "ngx.ctx" tables */
#define ngx_stream_lua_ctx_tables_key  "ngx_lua_ctx_tables"


/* char whose address we use as the key in Lua vm registry for
 * user code cache table */
extern char ngx_stream_lua_code_cache_key;

/* char whose address we use as the key in Lua vm registry for
 * regex cache table  */
extern char ngx_stream_lua_regex_cache_key;

/* char whose address we use as the key in Lua vm registry for
 * socket connection pool table */
extern char ngx_stream_lua_socket_pool_key;

/* coroutine anchoring table key in Lua VM registry */
extern char ngx_stream_lua_coroutines_key;


#endif /* _NGX_STREAM_LUA_UTIL_H_INCLUDED_ */
