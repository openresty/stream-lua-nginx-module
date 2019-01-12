
/*
 * !!! DO NOT EDIT DIRECTLY !!!
 * This file was automatically generated from the following template:
 *
 * src/subsys/ngx_subsys_lua_socket_tcp.h.tt2
 */


/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_STREAM_LUA_SOCKET_TCP_H_INCLUDED_
#define _NGX_STREAM_LUA_SOCKET_TCP_H_INCLUDED_


#include "ngx_stream_lua_common.h"


#define NGX_STREAM_LUA_SOCKET_FT_ERROR         0x0001
#define NGX_STREAM_LUA_SOCKET_FT_TIMEOUT       0x0002
#define NGX_STREAM_LUA_SOCKET_FT_CLOSED        0x0004
#define NGX_STREAM_LUA_SOCKET_FT_RESOLVER      0x0008
#define NGX_STREAM_LUA_SOCKET_FT_BUFTOOSMALL   0x0010
#define NGX_STREAM_LUA_SOCKET_FT_NOMEM         0x0020
#define NGX_STREAM_LUA_SOCKET_FT_PARTIALWRITE  0x0040
#define NGX_STREAM_LUA_SOCKET_FT_CLIENTABORT   0x0080
#define NGX_STREAM_LUA_SOCKET_FT_SSL           0x0100


typedef struct ngx_stream_lua_socket_tcp_upstream_s
        ngx_stream_lua_socket_tcp_upstream_t;


typedef
    int (*ngx_stream_lua_socket_tcp_retval_handler)(ngx_stream_lua_request_t *r,
        ngx_stream_lua_socket_tcp_upstream_t *u, lua_State *L);


typedef void (*ngx_stream_lua_socket_tcp_upstream_handler_pt)
    (ngx_stream_lua_request_t *r, ngx_stream_lua_socket_tcp_upstream_t *u);


typedef struct {
    lua_State                         *lua_vm;

    /* active connections == out-of-pool reused connections
     *                       + in-pool connections */
    ngx_uint_t                         active_connections;

    /* queues of ngx_stream_lua_socket_pool_item_t: */
    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    u_char                             key[1];

} ngx_stream_lua_socket_pool_t;


struct ngx_stream_lua_socket_tcp_upstream_s {
    ngx_stream_lua_socket_tcp_retval_handler            read_prepare_retvals;
    ngx_stream_lua_socket_tcp_retval_handler            write_prepare_retvals;
    ngx_stream_lua_socket_tcp_upstream_handler_pt       read_event_handler;
    ngx_stream_lua_socket_tcp_upstream_handler_pt       write_event_handler;

    ngx_stream_lua_socket_pool_t            *socket_pool;

    ngx_stream_lua_loc_conf_t               *conf;
    ngx_stream_lua_cleanup_pt               *cleanup;
    ngx_stream_lua_request_t                *request;

    ngx_peer_connection_t            peer;

    ngx_msec_t                       read_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       connect_timeout;

    ngx_stream_upstream_resolved_t          *resolved;

    ngx_chain_t                     *bufs_in; /* input data buffers */
    ngx_chain_t                     *buf_in; /* last input data buffer */
    ngx_buf_t                        buffer; /* receive buffer */

    size_t                           length;
    size_t                           rest;

    ngx_err_t                        socket_errno;

    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;

    size_t                           request_len;
    ngx_chain_t                     *request_bufs;

    ngx_stream_lua_co_ctx_t                 *read_co_ctx;
    ngx_stream_lua_co_ctx_t                 *write_co_ctx;

    ngx_uint_t                       reused;

#if (NGX_STREAM_SSL)
    ngx_str_t                        ssl_name;
#endif

    unsigned                         ft_type:16;
    unsigned                         no_close:1;
    unsigned                         conn_waiting:1;
    unsigned                         read_waiting:1;
    unsigned                         write_waiting:1;
    unsigned                         eof:1;
    unsigned                         body_downstream:1;
    unsigned                         raw_downstream:1;
    unsigned                         read_closed:1;
    unsigned                         write_closed:1;
    unsigned                         read_consumed:1;
#if (NGX_STREAM_SSL)
    unsigned                         ssl_verify:1;
    unsigned                         ssl_session_reuse:1;
#endif
};


typedef struct ngx_stream_lua_dfa_edge_s  ngx_stream_lua_dfa_edge_t;


struct ngx_stream_lua_dfa_edge_s {
    ngx_stream_lua_dfa_edge_t       *next;
    int                              new_state;
    u_char                           chr;
};


typedef struct {
    ngx_stream_lua_socket_tcp_upstream_t        *upstream;

    ngx_str_t                            pattern;
    ngx_stream_lua_dfa_edge_t          **recovering;
    int                                  state;

    unsigned                             inclusive:1;
} ngx_stream_lua_socket_compiled_pattern_t;


typedef struct {
    ngx_stream_lua_socket_pool_t            *socket_pool;

    ngx_queue_t                      queue;
    ngx_connection_t                *connection;

    socklen_t                        socklen;
    struct sockaddr_storage          sockaddr;

    ngx_uint_t                       reused;

} ngx_stream_lua_socket_pool_item_t;


void ngx_stream_lua_inject_socket_tcp_api(ngx_log_t *log, lua_State *L);
void ngx_stream_lua_cleanup_conn_pools(lua_State *L);
int ngx_stream_lua_req_socket_tcp(lua_State *L);


#endif /* _NGX_STREAM_LUA_SOCKET_TCP_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
