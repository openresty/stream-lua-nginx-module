
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/ngx_subsys_lua_misc.c.tt2
 */


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
    int                          status;
    ngx_stream_lua_request_t    *r;
    u_char                      *p;
    size_t                       len;
    ngx_stream_lua_ctx_t        *ctx;

    r = ngx_stream_lua_get_req(L);
    if (r == NULL) {
        lua_pushnil(L);
        return 1;
    }

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        lua_pushnil(L);
        return 1;
    }

    p = (u_char *) luaL_checklstring(L, -1, &len);

    dd("ngx get %s", p);

    if (len == sizeof("status") - 1
        && ngx_strncmp(p, "status", sizeof("status") - 1) == 0)
    {
        ngx_stream_lua_check_fake_request(L, r);

    /* same as $status */

    status = r->session->status;

        lua_pushinteger(L, status);
        return 1;
    }

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
    ngx_stream_lua_request_t    *r;
    u_char                      *p;
    size_t                       len;

    /* we skip the first argument that is the table */
    p = (u_char *) luaL_checklstring(L, 2, &len);


    if (len == sizeof("ctx") - 1
        && ngx_strncmp(p, "ctx", sizeof("ctx") - 1) == 0)
    {
        r = ngx_stream_lua_get_req(L);
        if (r == NULL) {
            return luaL_error(L, "no request object found");
        }

        return ngx_stream_lua_ngx_set_ctx(L);
    }

    lua_rawset(L, -3);
    return 0;
}




int
ngx_stream_lua_ffi_get_conf_env(u_char *name, u_char **env_buf,
    size_t *name_len)
{
    ngx_uint_t            i;
    ngx_str_t            *var;
    ngx_core_conf_t      *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    var = ccf->env.elts;

    for (i = 0; i < ccf->env.nelts; i++) {
        if (var[i].data[var[i].len] == '='
            && ngx_strncmp(name, var[i].data, var[i].len) == 0)
        {
            *env_buf = var[i].data;
            *name_len = var[i].len;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
