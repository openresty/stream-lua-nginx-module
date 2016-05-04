
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_STREAM_LUA_ARGS_H_INCLUDED_
#define _NGX_STREAM_LUA_ARGS_H_INCLUDED_


#include "ngx_stream_lua_common.h"


void ngx_stream_lua_inject_req_args_api(lua_State *L);
int ngx_stream_lua_parse_args(lua_State *L, u_char *buf, u_char *last, int max);


#endif /* _NGX_STREAM_LUA_ARGS_H_INCLUDED_ */
