

/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 */


#ifndef _NGX_STREAM_LUA_DIRECTIVE_H_INCLUDED_
#define _NGX_STREAM_LUA_DIRECTIVE_H_INCLUDED_


#include "ngx_stream_lua_common.h"


char *ngx_stream_lua_init_by_lua(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_stream_lua_init_by_lua_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_stream_lua_content_by_lua_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_stream_lua_content_by_lua(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_stream_lua_conf_lua_block_parse(ngx_conf_t *cf,
    ngx_command_t *cmd);
char *ngx_stream_lua_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_stream_lua_code_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_stream_lua_package_cpath(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_stream_lua_package_path(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_stream_lua_shared_dict(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_stream_lua_init_worker_by_lua(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_stream_lua_init_worker_by_lua_block(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


#endif /* _NGX_STREAM_LUA_DIRECTIVE_H_INCLUDED_ */
