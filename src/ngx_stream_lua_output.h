
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_STREAM_LUA_OUTPUT_H_INCLUDED_
#define _NGX_STREAM_LUA_OUTPUT_H_INCLUDED_


#include "ngx_stream_lua_common.h"


void ngx_stream_lua_inject_output_api(lua_State *L);
size_t ngx_stream_lua_calc_strlen_in_table(lua_State *L, int index, int arg_i,
    unsigned strict);
u_char *ngx_stream_lua_copy_str_in_table(lua_State *L, int index, u_char *dst);
ngx_int_t ngx_stream_lua_flush_resume_helper(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx);
ngx_int_t ngx_stream_lua_send_chain_link(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx, ngx_chain_t *in);


#endif /* _NGX_STREAM_LUA_OUTPUT_H_INCLUDED_ */
