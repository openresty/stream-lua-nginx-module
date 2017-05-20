
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_STREAM_LUA_SOCKET_UDP_H_INCLUDED_
#define _NGX_STREAM_LUA_SOCKET_UDP_H_INCLUDED_


#include "ngx_stream_lua_common.h"


typedef struct ngx_stream_lua_socket_udp_upstream_s
    ngx_stream_lua_socket_udp_upstream_t;


typedef
    int (*ngx_stream_lua_socket_udp_retval_handler)(ngx_stream_session_t *s,
        ngx_stream_lua_socket_udp_upstream_t *u, lua_State *L);


typedef void (*ngx_stream_lua_socket_udp_upstream_handler_pt)
    (ngx_stream_session_t *s, ngx_stream_lua_socket_udp_upstream_t *u);


typedef struct {
    ngx_connection_t         *connection;
    ngx_addr_t               *local;
    struct sockaddr          *sockaddr;
    socklen_t                 socklen;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    unsigned                   transparent:1;
#endif
    ngx_str_t                 server;
    ngx_log_t                 log;
} ngx_stream_lua_udp_connection_t;


struct ngx_stream_lua_socket_udp_upstream_s {
    ngx_stream_lua_socket_udp_retval_handler          prepare_retvals;
    ngx_stream_lua_socket_udp_upstream_handler_pt     read_event_handler;

    ngx_stream_lua_srv_conf_t         *conf;
    ngx_pool_cleanup_pt               *cleanup;
    ngx_stream_session_t              *session;
    ngx_stream_lua_udp_connection_t    udp_connection;

    ngx_msec_t                         read_timeout;

    ngx_stream_lua_resolved_t         *resolved;

    ngx_uint_t                       ft_type;
    ngx_err_t                        socket_errno;
    size_t                           received; /* for receive */
    size_t                           recv_buf_size;

    ngx_stream_lua_co_ctx_t         *co_ctx;
    unsigned                         waiting; /* :1 */
};


void ngx_stream_lua_inject_socket_udp_api(ngx_log_t *log, lua_State *L);


#endif /* _NGX_STREAM_LUA_SOCKET_UDP_H_INCLUDED_ */
