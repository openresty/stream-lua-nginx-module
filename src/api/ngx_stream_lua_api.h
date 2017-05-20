
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_STREAM_LUA_API_H_INCLUDED_
#define _NGX_STREAM_LUA_API_H_INCLUDED_


#include <nginx.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <lua.h>
#include <stdint.h>


/* Public API for other Nginx modules */


#define ngx_stream_lua_version  10006


typedef struct {
    uint8_t         type;

    union {
        int         b; /* boolean */
        lua_Number  n; /* number */
        ngx_str_t   s; /* string */
    } value;

} ngx_stream_lua_value_t;


lua_State *ngx_stream_lua_get_global_state(ngx_conf_t *cf);

ngx_stream_session_t *ngx_stream_lua_get_session(lua_State *L);

ngx_int_t ngx_stream_lua_add_package_preload(ngx_conf_t *cf,
    const char *package, lua_CFunction func);

ngx_shm_zone_t *ngx_stream_lua_find_zone(u_char *name_data, size_t name_len);


#endif /* _NGX_STREAM_LUA_API_H_INCLUDED_ */
