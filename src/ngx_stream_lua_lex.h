
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_STREAM_LUA_LEX_H_INCLUDED_
#define _NGX_STREAM_LUA_LEX_H_INCLUDED_


#include "ngx_stream_lua_common.h"


int ngx_stream_lua_lex(const u_char *const s, size_t len, int *const ovec);


#endif
