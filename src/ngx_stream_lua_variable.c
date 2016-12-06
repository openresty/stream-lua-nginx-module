
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_variable.h"
#include "ngx_stream_lua_util.h"


static int ngx_stream_lua_var_get(lua_State *L);
static int ngx_stream_lua_var_set(lua_State *L);
static int ngx_stream_lua_variable_pid(lua_State *L);
static int ngx_stream_lua_variable_remote_addr(lua_State *L,
    ngx_stream_session_t *s);
static int ngx_stream_lua_variable_binary_remote_addr(lua_State *L,
    ngx_stream_session_t *s);
static int ngx_stream_lua_variable_remote_port(lua_State *L,
    ngx_stream_session_t *s);
static int ngx_stream_lua_variable_server_addr(lua_State *L,
    ngx_stream_session_t *s);
static int ngx_stream_lua_variable_server_port(lua_State *L,
    ngx_stream_session_t *s);
static int ngx_stream_lua_variable_connection(lua_State *L,
    ngx_stream_session_t *s);
static int ngx_stream_lua_variable_nginx_version(lua_State *L);


void
ngx_stream_lua_inject_variable_api(lua_State *L)
{
    /* {{{ register reference maps */
    lua_newtable(L);    /* ngx.var */

    lua_createtable(L, 0, 2 /* nrec */); /* metatable for .var */
    lua_pushcfunction(L, ngx_stream_lua_var_get);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, ngx_stream_lua_var_set);
    lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "var");
}


/* Get pseudo NGINX variables content
 *
 * @retval Always return a string or nil on Lua stack. Return nil when failed
 * to get content, and actual content string when found the specified variable.
 */
static int
ngx_stream_lua_var_get(lua_State *L)
{
    ngx_stream_session_t        *s;
    ngx_stream_lua_ctx_t        *ctx;
    u_char                      *p;
    size_t                       len;

    s = ngx_stream_lua_get_session(L);
    if (s == NULL) {
        return luaL_error(L, "no session found");
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no session ctx found");
    }

    if (lua_type(L, -1) != LUA_TSTRING) {
        return luaL_error(L, "bad variable name");
    }

    p = (u_char *) lua_tolstring(L, -1, &len);

    switch (len) {

    case sizeof("pid") - 1:
        if (ngx_strncmp(p, "pid", sizeof("pid") - 1) == 0) {
            return ngx_stream_lua_variable_pid(L);
        }
        break;

    case sizeof("connection") - 1:
        if (ngx_strncmp(p, "connection", sizeof("connection") - 1) == 0) {
            return ngx_stream_lua_variable_connection(L, s);
        }
        break;

    case sizeof("remote_addr") - 1:
        if (ngx_strncmp(p, "remote_addr", sizeof("remote_addr") - 1) == 0) {
            return ngx_stream_lua_variable_remote_addr(L, s);
        }

        if (ngx_strncmp(p, "remote_port", sizeof("remote_port") - 1) == 0) {
            return ngx_stream_lua_variable_remote_port(L, s);
        }

        if (ngx_strncmp(p, "server_addr", sizeof("server_addr") - 1) == 0) {
            return ngx_stream_lua_variable_server_addr(L, s);
        }

        if (ngx_strncmp(p, "server_port", sizeof("server_port") - 1) == 0) {
            return ngx_stream_lua_variable_server_port(L, s);
        }
        break;

    case sizeof("nginx_version") - 1:
        if (ngx_strncmp(p, "nginx_version", sizeof("nginx_version") - 1) == 0) {
            return ngx_stream_lua_variable_nginx_version(L);
        }
        break;

    case sizeof("binary_remote_addr") - 1:
        if (ngx_strncmp(p, "binary_remote_addr",
                       sizeof("binary_remote_addr") - 1) == 0)
        {
            return ngx_stream_lua_variable_binary_remote_addr(L, s);
        }
        break;

    default:
        break;
    }

    lua_pushnil(L);
    return 1;
}


static int
ngx_stream_lua_variable_pid(lua_State *L)
{
    lua_pushinteger(L, (lua_Integer) ngx_pid);
    lua_tostring(L, -1);
    return 1;
}


static int
ngx_stream_lua_variable_remote_addr(lua_State *L, ngx_stream_session_t *s)
{
    lua_pushlstring(L, (const char *) s->connection->addr_text.data,
                    (size_t) s->connection->addr_text.len);
    return 1;
}


static int
ngx_stream_lua_variable_binary_remote_addr(lua_State *L,
    ngx_stream_session_t *s)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (s->connection->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;

        lua_pushlstring(L, (const char *) sin6->sin6_addr.s6_addr,
                        sizeof(struct in6_addr));
        return 1;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) s->connection->sockaddr;

        lua_pushlstring(L, (const char *) &sin->sin_addr, sizeof(in_addr_t));
        return 1;
    }
}


static int
ngx_stream_lua_variable_remote_port(lua_State *L, ngx_stream_session_t *s)
{
    ngx_uint_t            port;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (s->connection->sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;
        port = ntohs(sin6->sin6_port);
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        port = 0;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) s->connection->sockaddr;
        port = ntohs(sin->sin_port);
        break;
    }

    if (port > 0 && port < 65536) {
        lua_pushnumber(L, port);
        lua_tostring(L, -1);
        return 1;
    }

    lua_pushnil(L);
    return 1;
}


static int
ngx_stream_lua_variable_server_addr(lua_State *L, ngx_stream_session_t *s)
{
    ngx_str_t  str;
    u_char     addr[NGX_SOCKADDR_STRLEN];

    str.len = NGX_SOCKADDR_STRLEN;
    str.data = addr;

    if (ngx_connection_local_sockaddr(s->connection, &str, 0) != NGX_OK) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushlstring(L, (const char *) str.data, (size_t) str.len);
    return 1;
}


static int
ngx_stream_lua_variable_server_port(lua_State *L, ngx_stream_session_t *s)
{
    ngx_uint_t            port;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (ngx_connection_local_sockaddr(s->connection, NULL, 0) != NGX_OK) {
        lua_pushnil(L);
        return 1;
    }

    switch (s->connection->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->local_sockaddr;
        port = ntohs(sin6->sin6_port);
        break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        port = 0;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) s->connection->local_sockaddr;
        port = ntohs(sin->sin_port);
        break;
    }

    if (port > 0 && port < 65536) {
        lua_pushnumber(L, port);
        lua_tostring(L, -1);
        return 1;
    }

    lua_pushnil(L);
    return 1;
}


static int
ngx_stream_lua_variable_connection(lua_State *L,
    ngx_stream_session_t *s)
{
    lua_pushnumber(L, (lua_Integer) s->connection->number);
    lua_tostring(L, -1);

    return 1;
}


static int
ngx_stream_lua_variable_nginx_version(lua_State *L)
{
    lua_pushlstring(L, (const char *) NGINX_VERSION, sizeof(NGINX_VERSION) - 1);
    return 1;
}


/**
 * Can not set pseudo NGINX variables content
 * */
static int
ngx_stream_lua_var_set(lua_State *L)
{
    return luaL_error(L, "can not set variable");
}
