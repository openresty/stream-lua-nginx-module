/*
 * Copyright (C) Yichun Zhang (agentzh)
 */

#ifndef _NGX_STREAM_LUA_SSL_VERIFYBY_H_INCLUDED_
#define _NGX_STREAM_LUA_SSL_VERIFYBY_H_INCLUDED_

#include "ngx_stream_lua_common.h"

#if (NGX_STREAM_SSL)

ngx_int_t ngx_stream_lua_ssl_verify_handler_inline(
    ngx_stream_lua_request_t *r, ngx_stream_lua_srv_conf_t *lscf, lua_State *L);

ngx_int_t ngx_stream_lua_ssl_verify_handler_file(
    ngx_stream_lua_request_t *r, ngx_stream_lua_srv_conf_t *lscf, lua_State *L);

char *ngx_stream_lua_ssl_verify_by_lua_block(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

char *ngx_stream_lua_ssl_verify_by_lua(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

int ngx_stream_lua_ssl_verify_handler(X509_STORE_CTX *x509_store, void *arg);

#endif  /* NGX_STREAM_SSL */
#endif /* _NGX_STREAM_LUA_SSL_VERIFYBY_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
