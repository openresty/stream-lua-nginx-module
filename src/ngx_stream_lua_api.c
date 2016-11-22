
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_common.h"
#include "api/ngx_stream_lua_api.h"
#include "ngx_stream_lua_shdict.h"
#include "ngx_stream_lua_util.h"


lua_State *
ngx_stream_lua_get_global_state(ngx_conf_t *cf)
{
    ngx_stream_lua_main_conf_t *lmcf;

    lmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_lua_module);

    return lmcf->lua;
}


ngx_stream_session_t *
ngx_stream_lua_get_session(lua_State *L)
{
    ngx_stream_session_t    *s;

    lua_getglobal(L, ngx_stream_lua_session_key);
    s = lua_touserdata(L, -1);
    lua_pop(L, 1);

    return s;
}


ngx_int_t
ngx_stream_lua_add_package_preload(ngx_conf_t *cf, const char *package,
    lua_CFunction func)
{
    lua_State                       *L;
    ngx_stream_lua_main_conf_t      *lmcf;
    ngx_stream_lua_preload_hook_t   *hook;

    lmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_lua_module);

    L = lmcf->lua;

    if (L) {
        lua_getglobal(L, "package");
        lua_getfield(L, -1, "preload");
        lua_pushcfunction(L, func);
        lua_setfield(L, -2, package);
        lua_pop(L, 2);
    }

    /* we always register preload_hooks since we always create new Lua VMs
     * when lua code cache is off. */

    if (lmcf->preload_hooks == NULL) {
        lmcf->preload_hooks =
            ngx_array_create(cf->pool, 4,
                             sizeof(ngx_stream_lua_preload_hook_t));

        if (lmcf->preload_hooks == NULL) {
            return NGX_ERROR;
        }
    }

    hook = ngx_array_push(lmcf->preload_hooks);
    if (hook == NULL) {
        return NGX_ERROR;
    }

    hook->package = (u_char *) package;
    hook->loader = func;

    return NGX_OK;
}
