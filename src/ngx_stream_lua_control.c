
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_control.h"
#include "ngx_stream_lua_util.h"
#include "ngx_stream_lua_coroutine.h"





static int ngx_stream_lua_ngx_exit(lua_State *L);
static int ngx_stream_lua_on_abort(lua_State *L);


void
ngx_stream_lua_inject_control_api(ngx_log_t *log, lua_State *L)
{


    /* ngx.exit */

    lua_pushcfunction(L, ngx_stream_lua_ngx_exit);
    lua_setfield(L, -2, "exit");

    /* ngx.on_abort */

    lua_pushcfunction(L, ngx_stream_lua_on_abort);
    lua_setfield(L, -2, "on_abort");
}





static int
ngx_stream_lua_ngx_exit(lua_State *L)
{
    ngx_int_t                    rc;
    ngx_stream_lua_request_t          *r;
    ngx_stream_lua_ctx_t          *ctx;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting one argument");
    }

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request object found");
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT
                               | NGX_STREAM_LUA_CONTEXT_TIMER

        );

    rc = (ngx_int_t) luaL_checkinteger(L, 1);



    dd("setting exit code: %d", (int) rc);

    ctx->exit_code = rc;
    ctx->exited = 1;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua exit with code %i", ctx->exit_code);



    dd("calling yield");
    return lua_yield(L, 0);
}


static int
ngx_stream_lua_on_abort(lua_State *L)
{
    ngx_stream_lua_request_t           *r;
    ngx_stream_lua_ctx_t           *ctx;
    ngx_stream_lua_co_ctx_t        *coctx = NULL;
    ngx_stream_lua_loc_conf_t      *llcf;

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        return luaL_error(L, "no request found");
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no request ctx found");
    }

    ngx_stream_lua_check_fake_request2(L, r, ctx);

    if (ctx->on_abort_co_ctx) {
        lua_pushnil(L);
        lua_pushliteral(L, "duplicate call");
        return 2;
    }

    llcf = ngx_stream_lua_get_module_loc_conf(r, ngx_stream_lua_module);
    if (!llcf->check_client_abort) {
        lua_pushnil(L);
        lua_pushliteral(L, "lua_check_client_abort is off");
        return 2;
    }

    ngx_stream_lua_coroutine_create_helper(L, r, ctx, &coctx);

    lua_pushlightuserdata(L, &ngx_stream_lua_coroutines_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_pushvalue(L, -2);

    dd("on_wait thread 1: %p", lua_tothread(L, -1));

    coctx->co_ref = luaL_ref(L, -2);
    lua_pop(L, 1);

    coctx->is_uthread = 1;
    ctx->on_abort_co_ctx = coctx;

    dd("on_wait thread 2: %p", coctx->co);

    coctx->co_status = NGX_STREAM_LUA_CO_SUSPENDED;
    coctx->parent_co_ctx = ctx->cur_co_ctx;

    lua_pushinteger(L, 1);
    return 1;
}


#ifndef NGX_LUA_NO_FFI_API
int
ngx_stream_lua_ffi_exit(ngx_stream_lua_request_t *r, int status, u_char *err,
    size_t *errlen)
{
    ngx_stream_lua_ctx_t       *ctx;

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        *errlen = ngx_snprintf(err, *errlen, "no request ctx found") - err;
        return NGX_ERROR;
    }

    if (ngx_stream_lua_ffi_check_context(ctx, NGX_STREAM_LUA_CONTEXT_REWRITE
                                       | NGX_STREAM_LUA_CONTEXT_ACCESS
                                       | NGX_STREAM_LUA_CONTEXT_CONTENT
                                       | NGX_STREAM_LUA_CONTEXT_TIMER
                                       | NGX_STREAM_LUA_CONTEXT_HEADER_FILTER
                                       | NGX_STREAM_LUA_CONTEXT_BALANCER
                                       | NGX_STREAM_LUA_CONTEXT_SSL_CERT
                                       | NGX_STREAM_LUA_CONTEXT_SSL_SESS_STORE
                                       | NGX_STREAM_LUA_CONTEXT_SSL_SESS_FETCH,
                                       err, errlen)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ctx->context & (NGX_STREAM_LUA_CONTEXT_SSL_CERT
                        | NGX_STREAM_LUA_CONTEXT_SSL_SESS_STORE
                        | NGX_STREAM_LUA_CONTEXT_SSL_SESS_FETCH))
    {

#if (NGX_STREAM_SSL)

        ctx->exit_code = status;
        ctx->exited = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, r->connection->log, 0,
                       "lua exit with code %d", status);

        if (ctx->context == NGX_STREAM_LUA_CONTEXT_SSL_SESS_STORE) {
            return NGX_DONE;
        }

        return NGX_OK;

#else

        return NGX_ERROR;

#endif
    }



    ctx->exit_code = status;
    ctx->exited = 1;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, r->connection->log, 0,
                   "lua exit with code %i", ctx->exit_code);

    if (ctx->context & (NGX_STREAM_LUA_CONTEXT_HEADER_FILTER
                        | NGX_STREAM_LUA_CONTEXT_BALANCER))
    {
        return NGX_DONE;
    }

    return NGX_OK;
}
#endif  /* NGX_LUA_NO_FFI_API */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
