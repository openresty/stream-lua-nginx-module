#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_output.h"
#include "ngx_stream_lua_util.h"
#include "ngx_stream_lua_contentby.h"
#include <math.h>


static int ngx_stream_lua_ngx_say(lua_State *L);
static int ngx_stream_lua_ngx_print(lua_State *L);
static int ngx_stream_lua_ngx_flush(lua_State *L);
static int ngx_stream_lua_ngx_eof(lua_State *L);
static int ngx_stream_lua_ngx_echo(lua_State *L, unsigned newline);
static void ngx_stream_lua_flush_cleanup(ngx_stream_lua_co_ctx_t *coctx);


#define NGX_STREAM_LUA_MAX_ERROR_STR   128


static int
ngx_stream_lua_ngx_print(lua_State *L)
{
    dd("calling lua print");
    return ngx_stream_lua_ngx_echo(L, 0);
}


static int
ngx_stream_lua_ngx_say(lua_State *L)
{
    dd("calling");
    return ngx_stream_lua_ngx_echo(L, 1);
}


static int
ngx_stream_lua_ngx_echo(lua_State *L, unsigned newline)
{
    ngx_stream_session_t        *s;
    ngx_stream_lua_ctx_t        *ctx;
    const char                  *p;
    size_t                       len;
    size_t                       size;
    ngx_buf_t                   *b;
    ngx_chain_t                 *cl;
    ngx_int_t                    rc;
    int                          i;
    int                          nargs;
    int                          type;
    ngx_err_t                    err;
    const char                  *msg;
    u_char                       errbuf[NGX_STREAM_LUA_MAX_ERROR_STR];

    s = ngx_stream_lua_get_session(L);
    if (s == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (s->connection->type == SOCK_DGRAM) {
        return luaL_error(L, "not supported in udp requests");
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);

    if (ctx == NULL) {
        return luaL_error(L, "no session ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT);

#if 0
    if (ctx->acquired_raw_req_socket) {
        lua_pushnil(L);
        lua_pushliteral(L, "raw session socket acquired");
        return 2;
    }
#endif

    if (ctx->eof) {
        lua_pushnil(L);
        lua_pushliteral(L, "seen eof");
        return 2;
    }

    nargs = lua_gettop(L);
    size = 0;

    for (i = 1; i <= nargs; i++) {

        type = lua_type(L, i);

        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:

                lua_tolstring(L, i, &len);
                size += len;
                break;

            case LUA_TNIL:

                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:

                if (lua_toboolean(L, i)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TTABLE:

                size += ngx_stream_lua_calc_strlen_in_table(L, i, i,
                                                            0 /* strict */);
                break;

            case LUA_TLIGHTUSERDATA:

                dd("userdata: %p", lua_touserdata(L, i));

                if (lua_touserdata(L, i) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:

                msg = lua_pushfstring(L, "string, number, boolean, nil, "
                                      "ngx.null, or array table expected, "
                                      "but got %s", lua_typename(L, type));

                return luaL_argerror(L, i, msg);
        }
    }

    if (newline) {
        size += sizeof("\n") - 1;
    }

    if (size == 0) {
        /* do nothing for empty strings */
        lua_pushinteger(L, 1);
        return 1;
    }

    cl = ngx_stream_lua_chain_get_free_buf(s->connection->log,
                                           s->connection->pool,
                                           &ctx->free_bufs, size);

    if (cl == NULL) {
        return luaL_error(L, "no memory");
    }

    b = cl->buf;

    for (i = 1; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                p = lua_tolstring(L, i, &len);
                b->last = ngx_copy(b->last, (u_char *) p, len);
                break;

            case LUA_TNIL:
                *b->last++ = 'n';
                *b->last++ = 'i';
                *b->last++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    *b->last++ = 't';
                    *b->last++ = 'r';
                    *b->last++ = 'u';
                    *b->last++ = 'e';

                } else {
                    *b->last++ = 'f';
                    *b->last++ = 'a';
                    *b->last++ = 'l';
                    *b->last++ = 's';
                    *b->last++ = 'e';
                }

                break;

            case LUA_TTABLE:
                b->last = ngx_stream_lua_copy_str_in_table(L, i, b->last);
                break;

            case LUA_TLIGHTUSERDATA:
                *b->last++ = 'n';
                *b->last++ = 'u';
                *b->last++ = 'l';
                *b->last++ = 'l';
                break;

            default:
                return luaL_error(L, "impossible to reach here");
        }
    }

    if (newline) {
        *b->last++ = '\n';
    }

#if 0
    if (b->last != b->end) {
        return luaL_error(L, "buffer error: %p != %p", b->last, b->end);
    }
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   newline ? "stream lua say response"
                           : "stream lua print response");

    ngx_set_errno(0);

    rc = ngx_stream_lua_send_chain_link(s, ctx, cl);

    if (rc == NGX_ERROR) {
        err = ngx_errno;

        lua_pushnil(L);

        if (err) {
            size = ngx_strerror(err, errbuf, sizeof(errbuf)) - errbuf;
            ngx_strlow(errbuf, errbuf, size);
            lua_pushlstring(L, (char *) errbuf, size);

        } else {
            lua_pushliteral(L, "unknown");
        }

        return 2;
    }

    dd("downstream write: %d, buf len: %d", (int) rc,
       (int) (b->last - b->pos));

    lua_pushinteger(L, 1);
    return 1;
}


size_t
ngx_stream_lua_calc_strlen_in_table(lua_State *L, int index, int arg_i,
    unsigned strict)
{
    double              key;
    int                 max;
    int                 i;
    int                 type;
    size_t              size;
    size_t              len;
    const char         *msg;

    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    dd("table index: %d", index);

    max = 0;

    lua_pushnil(L); /* stack: table key */
    while (lua_next(L, index) != 0) { /* stack: table key value */
        dd("key type: %s", luaL_typename(L, -2));

        if (lua_type(L, -2) == LUA_TNUMBER) {

            key = lua_tonumber(L, -2);

            dd("key value: %d", (int) key);

            if (floor(key) == key && key >= 1) {
                if (key > max) {
                    max = (int) key;
                }

                lua_pop(L, 1); /* stack: table key */
                continue;
            }
        }

        /* not an array (non positive integer key) */
        lua_pop(L, 2); /* stack: table */

        luaL_argerror(L, arg_i, "non-array table found");
        return 0;
    }

    size = 0;

    for (i = 1; i <= max; i++) {
        lua_rawgeti(L, index, i); /* stack: table value */
        type = lua_type(L, -1);

        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:

                lua_tolstring(L, -1, &len);
                size += len;
                break;

            case LUA_TNIL:

                if (strict) {
                    goto bad_type;
                }

                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:

                if (strict) {
                    goto bad_type;
                }

                if (lua_toboolean(L, -1)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TTABLE:

                size += ngx_stream_lua_calc_strlen_in_table(L, -1, arg_i,
                                                            strict);
                break;

            case LUA_TLIGHTUSERDATA:

                if (strict) {
                    goto bad_type;
                }

                if (lua_touserdata(L, -1) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:

bad_type:

                msg = lua_pushfstring(L, "bad data type %s found",
                                      lua_typename(L, type));
                return luaL_argerror(L, arg_i, msg);
        }

        lua_pop(L, 1); /* stack: table */
    }

    return size;
}


u_char *
ngx_stream_lua_copy_str_in_table(lua_State *L, int index, u_char *dst)
{
    double               key;
    int                  max;
    int                  i;
    int                  type;
    size_t               len;
    u_char              *p;

    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    max = 0;

    lua_pushnil(L); /* stack: table key */
    while (lua_next(L, index) != 0) { /* stack: table key value */
        key = lua_tonumber(L, -2);
        if (key > max) {
            max = (int) key;
        }

        lua_pop(L, 1); /* stack: table key */
    }

    for (i = 1; i <= max; i++) {
        lua_rawgeti(L, index, i); /* stack: table value */
        type = lua_type(L, -1);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                p = (u_char *) lua_tolstring(L, -1, &len);
                dst = ngx_copy(dst, p, len);
                break;

            case LUA_TNIL:
                *dst++ = 'n';
                *dst++ = 'i';
                *dst++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, -1)) {
                    *dst++ = 't';
                    *dst++ = 'r';
                    *dst++ = 'u';
                    *dst++ = 'e';

                } else {
                    *dst++ = 'f';
                    *dst++ = 'a';
                    *dst++ = 'l';
                    *dst++ = 's';
                    *dst++ = 'e';
                }

                break;

            case LUA_TTABLE:
                dst = ngx_stream_lua_copy_str_in_table(L, -1, dst);
                break;

            case LUA_TLIGHTUSERDATA:

                *dst++ = 'n';
                *dst++ = 'u';
                *dst++ = 'l';
                *dst++ = 'l';
                break;

            default:
                luaL_error(L, "impossible to reach here");
                return NULL;
        }

        lua_pop(L, 1); /* stack: table */
    }

    return dst;
}


/**
 * Force flush out response content
 * */
static int
ngx_stream_lua_ngx_flush(lua_State *L)
{
    ngx_stream_session_t        *s;
    ngx_stream_lua_ctx_t        *ctx;
    int                          n;
    unsigned                     wait = 0;
    ngx_event_t                 *wev;
    ngx_stream_lua_srv_conf_t   *lscf;
    ngx_stream_lua_co_ctx_t     *coctx;

    n = lua_gettop(L);
    if (n > 1) {
        return luaL_error(L, "attempt to pass %d arguments, but accepted 0 "
                          "or 1", n);
    }

    s = ngx_stream_lua_get_session(L);

    if (s->connection->type == SOCK_DGRAM) {
        return luaL_error(L, "not supported in udp requests");
    }

    wait = 1;  /* always wait */

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no session ctx found");
    }

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT);

#if 0
    if (ctx->acquired_raw_req_socket) {
        lua_pushnil(L);
        lua_pushliteral(L, "raw session socket acquired");
        return 2;
    }
#endif

    coctx = ctx->cur_co_ctx;
    if (coctx == NULL) {
        return luaL_error(L, "no co ctx found");
    }

    if (ctx->eof) {
        lua_pushnil(L);
        lua_pushliteral(L, "seen eof");
        return 2;
    }

    wev = s->connection->write;

    if (wait && (ctx->downstream_busy_bufs || wev->delayed)) {
        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream lua flush requires waiting: busy bufs %p, "
                       "delayed %d", ctx->downstream_busy_bufs, wev->delayed);

        coctx->flushing = 1;
        ctx->flushing_coros++;

        /* mimic ngx_stream_set_write_handler */
        ctx->write_event_handler = ngx_stream_lua_content_wev_handler;

        lscf = ngx_stream_get_module_srv_conf(s, ngx_stream_lua_module);

        if (!wev->delayed) {
            ngx_add_timer(wev, lscf->send_timeout);
        }

        if (ngx_handle_write_event(wev, lscf->send_lowat) != NGX_OK) {
            if (wev->timer_set) {
                wev->delayed = 0;
                ngx_del_timer(wev);
            }

            lua_pushnil(L);
            lua_pushliteral(L, "connection broken");
            return 2;
        }

        ngx_stream_lua_cleanup_pending_operation(ctx->cur_co_ctx);
        coctx->cleanup = ngx_stream_lua_flush_cleanup;
        coctx->data = s;

        return lua_yield(L, 0);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream lua flush asynchronously");

    lua_pushinteger(L, 1);
    return 1;
}


/**
 * Send last_buf, terminate output stream
 * */
static int
ngx_stream_lua_ngx_eof(lua_State *L)
{
    ngx_stream_session_t      *s;
    ngx_stream_lua_ctx_t      *ctx;

    s = ngx_stream_lua_get_session(L);
    if (s == NULL) {
        return luaL_error(L, "no session object found");
    }

    if (s->connection->type == SOCK_DGRAM) {
        return luaL_error(L, "not supported in udp requests");
    }

    if (lua_gettop(L) != 0) {
        return luaL_error(L, "no argument is expected");
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);
    if (ctx == NULL) {
        return luaL_error(L, "no ctx found");
    }

#if 0
    if (ctx->acquired_raw_req_socket) {
        lua_pushnil(L);
        lua_pushliteral(L, "raw session socket acquired");
        return 2;
    }
#endif

    if (ctx->eof) {
        lua_pushnil(L);
        lua_pushliteral(L, "seen eof");
        return 2;
    }

    ctx->eof = 1;

    ngx_stream_lua_check_context(L, ctx, NGX_STREAM_LUA_CONTEXT_CONTENT);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream lua send eof");

    lua_pushinteger(L, 1);
    return 1;
}


void
ngx_stream_lua_inject_output_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_stream_lua_ngx_print);
    lua_setfield(L, -2, "print");

    lua_pushcfunction(L, ngx_stream_lua_ngx_say);
    lua_setfield(L, -2, "say");

    lua_pushcfunction(L, ngx_stream_lua_ngx_flush);
    lua_setfield(L, -2, "flush");

    lua_pushcfunction(L, ngx_stream_lua_ngx_eof);
    lua_setfield(L, -2, "eof");
}


ngx_int_t
ngx_stream_lua_flush_resume_helper(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx)
{
    int                          n;
    lua_State                   *vm;
    ngx_int_t                    rc;
    ngx_connection_t            *c;

    c = s->connection;

    ctx->cur_co_ctx->cleanup = NULL;

    /* push the return values */

    if (c->timedout) {
        lua_pushnil(ctx->cur_co_ctx->co);
        lua_pushliteral(ctx->cur_co_ctx->co, "timeout");
        n = 2;

    } else if (c->error) {
        lua_pushnil(ctx->cur_co_ctx->co);
        lua_pushliteral(ctx->cur_co_ctx->co, "client aborted");
        n = 2;

    } else {
        lua_pushinteger(ctx->cur_co_ctx->co, 1);
        n = 1;
    }

    vm = ngx_stream_lua_get_lua_vm(s, ctx);
    rc = ngx_stream_lua_run_thread(vm, s, ctx, n);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "stream lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return ngx_stream_lua_run_posted_threads(c, vm, s, ctx);
    }

    if (rc == NGX_DONE) {
        ngx_stream_lua_finalize_session(s, NGX_DONE);
        return ngx_stream_lua_run_posted_threads(c, vm, s, ctx);
    }

    /* rc == NGX_ERROR || rc >= NGX_OK */

    if (ctx->entered_content_phase) {
        ngx_stream_lua_finalize_session(s, rc);
        return NGX_DONE;
    }

    return rc;
}


static void
ngx_stream_lua_flush_cleanup(ngx_stream_lua_co_ctx_t *coctx)
{
    ngx_stream_session_t                      *s;
    ngx_event_t                               *wev;
    ngx_stream_lua_ctx_t                      *ctx;

    coctx->flushing = 0;

    s = coctx->data;
    if (s == NULL) {
        return;
    }

    wev = s->connection->write;

    if (wev && wev->timer_set) {
        ngx_del_timer(wev);
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_lua_module);
    if (ctx == NULL) {
        return;
    }

    ctx->flushing_coros--;
}


ngx_int_t
ngx_stream_lua_send_chain_link(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_int_t                     rc;

#if 0
    if (ctx->acquired_raw_req_socket || (in && ctx->eof)) {
        dd("ctx->eof already set or raw req socket already acquired");
        return NGX_OK;
    }
#endif

    rc = ngx_chain_writer(&ctx->out_writer, in);

    if (rc == NGX_ERROR) {
        s->connection->error = 1;
    }

    ngx_chain_update_chains(s->connection->pool, &ctx->free_bufs,
                            &ctx->downstream_busy_bufs, &in,
                            (ngx_buf_tag_t) &ngx_stream_lua_module);

    ngx_stream_lua_assert(rc != NGX_AGAIN || ctx->downstream_busy_bufs);

    return rc;
}
