
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_phase.h"
#include "ngx_stream_lua_util.h"
#include "ngx_stream_lua_ctx.h"


static int ngx_stream_lua_ngx_get_phase(lua_State *L);


static int
ngx_stream_lua_ngx_get_phase(lua_State *L)
{
    ngx_stream_session_t          *r;
    ngx_stream_lua_ctx_t          *ctx;

    r = ngx_stream_lua_get_session(L);

    /* If we have no sessiong object, assume we are called from the "init"
     * phase. */

    if (r == NULL) {
        lua_pushliteral(L, "init");
        return 1;
    }

    ctx = ngx_stream_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no sessiong ctx found");
    }

    dd("context: %d", (int) ctx->context);

    switch (ctx->context) {
    case NGX_STREAM_LUA_CONTEXT_INIT_WORKER:
        lua_pushliteral(L, "init_worker");
        break;

    case NGX_STREAM_LUA_CONTEXT_CONTENT:
        lua_pushliteral(L, "content");
        break;

    case NGX_STREAM_LUA_CONTEXT_LOG:
        lua_pushliteral(L, "log");
        break;

    case NGX_STREAM_LUA_CONTEXT_TIMER:
        lua_pushliteral(L, "timer");
        break;

    case NGX_STREAM_LUA_CONTEXT_BALANCER:
        lua_pushliteral(L, "balancer");
        break;

    default:
        return luaL_error(L, "unknown phase: %d", (int) ctx->context);
    }

    return 1;
}


void
ngx_stream_lua_inject_phase_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_stream_lua_ngx_get_phase);
    lua_setfield(L, -2, "get_phase");
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
