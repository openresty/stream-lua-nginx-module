
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_STREAM_LUA_CTX_H_INCLUDED_
#define _NGX_STREAM_LUA_CTX_H_INCLUDED_


#include "ngx_stream_lua_common.h"


int ngx_stream_lua_ngx_get_ctx(lua_State *L);
int ngx_stream_lua_ngx_set_ctx(lua_State *L);
int ngx_stream_lua_ngx_set_ctx_helper(lua_State *L, ngx_stream_lua_request_t *r,
    ngx_stream_lua_ctx_t *ctx, int index);


#endif /* _NGX_STREAM_LUA_CTX_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
