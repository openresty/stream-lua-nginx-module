
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


    ngx_stream_lua_request_t          *r;
    u_char                      *p;
    size_t                       len;
    ngx_stream_lua_ctx_t          *ctx;

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
    ngx_stream_lua_request_t          *r;
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


#ifndef NGX_LUA_NO_FFI_API
int
ngx_stream_lua_ffi_get_resp_status(ngx_stream_lua_request_t *r)
{
    if (r->connection->fd == (ngx_socket_t) -1) {
        return NGX_STREAM_LUA_FFI_BAD_CONTEXT;
    }

    if (r->err_status) {
        return r->err_status;

    } else if (r->headers_out.status) {
        return r->headers_out.status;

    } else if (r->http_version == NGX_HTTP_VERSION_9) {
        return 9;

    } else {
        return 0;
    }
}


int
ngx_stream_lua_ffi_set_resp_status(ngx_stream_lua_request_t *r, int status)
{
    if (r->connection->fd == (ngx_socket_t) -1) {
        return NGX_STREAM_LUA_FFI_BAD_CONTEXT;
    }

    if (r->header_sent) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "attempt to set ngx.status after sending out "
                      "response headers");
        return NGX_DECLINED;
    }

    r->headers_out.status = status;

    if (r->err_status) {
        r->err_status = 0;
    }

    if (status == 101) {
        /*
         * XXX work-around a bug in the Nginx core older than 1.5.5
         * that 101 does not have a default status line
         */

        ngx_str_set(&r->headers_out.status_line, "101 Switching Protocols");

    } else {
        r->headers_out.status_line.len = 0;
    }

    return NGX_OK;
}


int
ngx_stream_lua_ffi_is_subrequest(ngx_stream_lua_request_t *r)
{
    if (r->connection->fd == (ngx_socket_t) -1) {
        return NGX_STREAM_LUA_FFI_BAD_CONTEXT;
    }

    return r != r->main;
}


int
ngx_stream_lua_ffi_headers_sent(ngx_stream_lua_request_t *r)
{
    ngx_stream_lua_ctx_t          *ctx;

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);
    if (ctx == NULL) {
        return NGX_STREAM_LUA_FFI_NO_REQ_CTX;
    }

    if (r->connection->fd == (ngx_socket_t) -1) {
        return NGX_STREAM_LUA_FFI_BAD_CONTEXT;
    }

    return r->header_sent ? 1 : 0;
}
#endif /* NGX_LUA_NO_FFI_API */


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
