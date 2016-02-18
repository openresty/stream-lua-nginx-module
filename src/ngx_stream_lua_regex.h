
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_STREAM_LUA_REGEX_H_INCLUDED_
#define _NGX_STREAM_LUA_REGEX_H_INCLUDED_


#include "ngx_stream_lua_common.h"
#include "ngx_stream_lua_script.h"


#if (NGX_PCRE)
void ngx_stream_lua_inject_regex_api(lua_State *L);
#endif


#endif /* _NGX_STREAM_LUA_REGEX_H_INCLUDED_ */
