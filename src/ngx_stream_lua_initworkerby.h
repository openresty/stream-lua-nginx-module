
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_STREAME_LUA_INITWORKERBY_H_INCLUDED_
#define _NGX_STREAME_LUA_INITWORKERBY_H_INCLUDED_


#include "ngx_stream_lua_common.h"


ngx_int_t ngx_stream_lua_init_worker_by_inline(ngx_log_t *log,
    ngx_stream_lua_main_conf_t *lmcf, lua_State *L);

ngx_int_t ngx_stream_lua_init_worker_by_file(ngx_log_t *log,
    ngx_stream_lua_main_conf_t *lmcf, lua_State *L);

ngx_int_t ngx_stream_lua_init_worker(ngx_cycle_t *cycle);


#endif /* _NGX_STREAME_LUA_INITWORKERBY_H_INCLUDED_ */
