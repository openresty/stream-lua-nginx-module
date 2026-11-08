# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);
plan tests => repeat_each() * blocks() * 3;

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
no_long_string();
log_level 'info';

add_block_preprocessor(sub {
    my $block = shift;
    my $config = $block->stream_config || '';
    $config .= <<'_EOC_';
lua_package_path "$prefix/html/?.lua;../lua-resty-core/lib/?.lua;;";
_EOC_
    $block->set_value("stream_config", $config);
    $block->set_value("user_files", <<'_EOC_');
>>> ssl_ctx.lua
local ffi = require "ffi"
local get_request = require("resty.core.base").get_request

ffi.cdef[[
    typedef struct ssl_ctx_st SSL_CTX;
    SSL_CTX *ngx_stream_lua_ffi_get_req_ssl_ctx(void *r, const char **err);
    SSL_CTX *SSL_get_SSL_CTX(const void *ssl);
    int SSL_CTX_get_verify_depth(const SSL_CTX *ctx);
]]

local C = ffi.C
local _M = {}

function _M.get(r)
    local err = ffi.new("const char *[1]")
    local ctx = C.ngx_stream_lua_ffi_get_req_ssl_ctx(r, err)
    return ctx, err[0] ~= nil and ffi.string(err[0]) or nil
end

function _M.depths()
    local ctx, err = _M.get(get_request())
    assert(ctx ~= nil, err)
    assert(ffi.istype("SSL_CTX *", ctx))
    assert(ctx == _M.get(get_request()))

    local ssl = assert(require("ngx.ssl").get_req_ssl_pointer())
    return C.SSL_CTX_get_verify_depth(ctx),
           C.SSL_CTX_get_verify_depth(C.SSL_get_SSL_CTX(ssl))
end

return _M
_EOC_
});

run_tests();

__DATA__

=== TEST 1: NULL request returns an error
--- stream_server_config
        content_by_lua_block {
            local ctx, err = require("ssl_ctx").get(nil)
            ngx.say(ctx == nil, ": ", err)
        }
--- stream_response
true: bad request
--- no_error_log
[error]


=== TEST 2: plain connection returns an error
--- stream_server_config
        content_by_lua_block {
            local r = require("resty.core.base").get_request()
            local ctx, err = require("ssl_ctx").get(r)
            ngx.say(ctx == nil, ": ", err)
        }
--- stream_response
true: bad request
--- no_error_log
[error]


=== TEST 3: TLS context is readable during certificate and content phases
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/ctx-3.sock ssl;
        server_name default.test;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
        ssl_verify_depth 3;

        ssl_certificate_by_lua_block {
            local session_depth, active_depth = require("ssl_ctx").depths()
            assert(session_depth == 3)
            assert(active_depth == 3)
        }

        content_by_lua_block {
            local session_depth, active_depth = require("ssl_ctx").depths()
            ngx.say(session_depth, ":", active_depth)
        }
    }
--- stream_server_config
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/ctx-3.sock"))
            assert(sock:sslhandshake(nil, "default.test", false))
            ngx.print(assert(sock:receive("*a")))
            assert(sock:close())
        }
--- stream_response
3:3
--- no_error_log
[error]


=== TEST 4: SNI preserves the original session context
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/ctx-4.sock ssl;
        server_name default.test;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
        ssl_verify_depth 3;

        ssl_certificate_by_lua_block {
            local session_depth, active_depth = require("ssl_ctx").depths()
            assert(session_depth == 3)
            assert(active_depth == 3)
        }

        content_by_lua_block {
            local session_depth, active_depth = require("ssl_ctx").depths()
            ngx.say(session_depth, ":", active_depth)
        }
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/ctx-4.sock ssl;
        server_name selected.test;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;
        ssl_verify_depth 7;

        ssl_certificate_by_lua_block {
            local session_depth, active_depth = require("ssl_ctx").depths()
            assert(session_depth == 3)
            assert(active_depth == 7)
        }

        content_by_lua_block {
            local session_depth, active_depth = require("ssl_ctx").depths()
            ngx.say(session_depth, ":", active_depth)
        }
    }
--- stream_server_config
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            assert(sock:connect("unix:$TEST_NGINX_HTML_DIR/ctx-4.sock"))
            assert(sock:sslhandshake(nil, "selected.test", false))
            ngx.print(assert(sock:receive("*a")))
            assert(sock:close())
        }
--- stream_response
3:7
--- no_error_log
[error]
