
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_misc.h"
#include "ngx_stream_lua_ctx.h"
#include "ngx_stream_lua_util.h"


static int ngx_stream_lua_ngx_get(lua_State *L);
static int ngx_stream_lua_ngx_set(lua_State *L);


void
ngx_stream_lua_inject_misc_api(lua_State *L)
{
    /* ngx. getter and setter */
    lua_createtable(L, 0, 2); /* metatable for .ngx */
    lua_pushcfunction(L, ngx_stream_lua_ngx_get);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, ngx_stream_lua_ngx_set);
    lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);
}


static int
ngx_stream_lua_ngx_get(lua_State *L)
{
    ngx_stream_session_t        *s;
    u_char                      *p;
    size_t                       len;
    ngx_stream_lua_ctx_t        *ctx;

    s = ngx_stream_lua_get_session(L);
    if (s == NULL) {
        lua_pushnil(L);
        return 1;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);
    if (ctx == NULL) {
        lua_pushnil(L);
        return 1;
    }

    p = (u_char *) luaL_checklstring(L, -1, &len);

    dd("ngx get %s", p);

    if (len == sizeof("ctx") - 1
        && ngx_strncmp(p, "ctx", sizeof("ctx") - 1) == 0)
    {
        return ngx_stream_lua_ngx_get_ctx(L);
    }

    dd("key %s not matched", p);

    lua_pushnil(L);
    return 1;
}


static int
ngx_stream_lua_ngx_set(lua_State *L)
{
    ngx_stream_session_t        *s;
    u_char                      *p;
    size_t                       len;

    /* we skip the first argument that is the table */
    p = (u_char *) luaL_checklstring(L, 2, &len);

    if (len == sizeof("ctx") - 1
        && ngx_strncmp(p, "ctx", sizeof("ctx") - 1) == 0)
    {
        s = ngx_stream_lua_get_session(L);
        if (s == NULL) {
            return luaL_error(L, "no session object found");
        }

        return ngx_stream_lua_ngx_set_ctx(L);
    }

    lua_rawset(L, -3);
    return 0;
}
