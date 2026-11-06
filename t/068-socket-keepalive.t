# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

plan tests => repeat_each() * (blocks() * 4 + 33);

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_HTML_DIR} = $HtmlDir;
$ENV{TEST_NGINX_REDIS_PORT} ||= 6379;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

log_level('debug');
no_long_string();
no_shuffle();

run_tests();

__DATA__

=== TEST 1: sanity
--- stream_server_config
    content_by_lua_block {
        local function go(port)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end
            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local bytes, err = sock:send("get __nil\r\n")
            if not bytes then
                ngx.say("failed to send request: ", err)
                return
            end
            ngx.say("request sent: ", bytes)

            local line, err, part = sock:receive()
            if line then
                ngx.say("received: ", line)

            else
                ngx.say("failed to receive a line: ", err, " [", part, "]")
            end

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to setkeepalive: ", err)
                return
            end
        end

        go($TEST_NGINX_MEMCACHED_PORT)
        go($TEST_NGINX_MEMCACHED_PORT)
    }
--- stream_response
connected: 1, reused: 0
request sent: 11
received: END
connected: 1, reused: 1
request sent: 11
received: END
--- error_log eval
qq{
lua tcp socket get keepalive peer: using connection
lua tcp socket keepalive create connection pool for key "127\.0\.0\.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"
}
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for "
]



=== TEST 2: free up the whole connection pool if no active connections
--- stream_server_config
    content_by_lua_block {
       local function go(port, keepalive)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port)
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end
            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local bytes, err = sock:send("get __nil\r\n")
            if not bytes then
                ngx.say("failed to send request: ", err)
                return
            end
            ngx.say("request sent: ", bytes)

            local line, err, part = sock:receive()
            if line then
                ngx.say("received: ", line)

            else
                ngx.say("failed to receive a line: ", err, " [", part, "]")
            end

            if keepalive then
                local ok, err = sock:setkeepalive()
                if not ok then
                    ngx.say("failed to setkeepalive: ", err)
                    return
                end

            else
                sock:close()
            end
        end

        go($TEST_NGINX_MEMCACHED_PORT, true)
        go($TEST_NGINX_MEMCACHED_PORT, false)
    }
--- stream_response
connected: 1, reused: 0
request sent: 11
received: END
connected: 1, reused: 1
request sent: 11
received: END
--- error_log eval
[
"lua tcp socket get keepalive peer: using connection",
"lua tcp socket keepalive: free connection pool for "
]
--- no_error_log
[error]



=== TEST 3: upstream sockets close prematurely
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 100ms;
        echo foo;
    }
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ngx.sleep(1)

        ngx.say("done")
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
done
--- error_log eval
[
"lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for "
]
--- no_error_log
[error]
--- timeout: 3



=== TEST 4: http keepalive
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 60s;
        echo foo;
    }
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ngx.sleep(1)

        ngx.say("done")
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log eval
[
"lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for "
]
--- timeout: 4



=== TEST 5: lua_socket_keepalive_timeout
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 60s;
        echo foo;
    }
--- stream_server_config
    lua_socket_keepalive_timeout 100ms;

    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ngx.sleep(1)

        ngx.say("done")
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 100 ms",
qr/lua tcp socket connection pool size: 30\b/]
--- timeout: 4



=== TEST 6: lua_socket_pool_size
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 60s;
        echo foo;
    }
--- stream_server_config
    lua_socket_keepalive_timeout 100ms;
    lua_socket_pool_size 1;

    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ngx.sleep(1)

        ngx.say("done")
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 100 ms",
qr/lua tcp socket connection pool size: 1\b/]
--- timeout: 4



=== TEST 7: "lua_socket_keepalive_timeout 0" means unlimited
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 60s;
        echo foo;
    }
--- stream_server_config
    lua_socket_keepalive_timeout 0;

    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ngx.sleep(1)

        ngx.say("done")
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive timeout: unlimited",
qr/lua tcp socket connection pool size: 30\b/]
--- timeout: 4



=== TEST 8: setkeepalive(timeout) overrides lua_socket_keepalive_timeout
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 60s;
        echo foo;
    }
--- stream_server_config
    lua_socket_keepalive_timeout 60s;

    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive(123)
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ngx.sleep(1)

        ngx.say("done")
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 123 ms",
qr/lua tcp socket connection pool size: 30\b/]
--- timeout: 4



=== TEST 9: sock:setkeepalive(timeout, size) overrides lua_socket_pool_size
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 100ms;
        echo foo;
    }
--- stream_server_config
    lua_socket_keepalive_timeout 60s;
    lua_socket_pool_size 100;

    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive(101, 25)
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ngx.sleep(1)

        ngx.say("done")
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 101 ms",
qr/lua tcp socket connection pool size: 25\b/]
--- timeout: 4



=== TEST 10: setkeepalive() 'pool_size' should be greater than zero
--- stream_server_config
    content_by_lua_block {
        local sock, err = ngx.socket.connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
        if not sock then
            ngx.say(err)
            return
        end

        local ok, err = pcall(sock.setkeepalive, sock, 0, 0)
        if not ok then
            ngx.say(err)
            return
        end
        ngx.say(ok)
    }
--- stream_response
bad argument #3 to '?' (bad "pool_size" option value: 0)
--- no_error_log
[error]



=== TEST 11: sock:keepalive_timeout(0) means unlimited
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 60s;
        echo foo;
    }
--- stream_server_config
    lua_socket_keepalive_timeout 1000ms;

    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive(0)
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ngx.sleep(1)

        ngx.say("done")
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
done
--- no_error_log
[error]
--- error_log eval
["lua tcp socket keepalive timeout: unlimited",
qr/lua tcp socket connection pool size: 30\b/]
--- timeout: 4



=== TEST 12: sanity (uds)
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock;
        default_type 'text/plain';
        server_tokens off;

        location /foo {
            echo foo;
            more_clear_headers Date;
        }
    }
--- stream_server_config
    content_by_lua_block {
        local function go(path)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("unix:" .. path)
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

            local bytes, err = sock:send(req)
            if not bytes then
                ngx.say("failed to send request: ", err)
                return
            end
            ngx.say("request sent: ", bytes)

            local reader = sock:receiveuntil("\r\n0\r\n\r\n")
            local data, err = reader()

            if not data then
                ngx.say("failed to receive response body: ", err)
                return
            end

            ngx.say("received response of ", #data, " bytes")

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go("$TEST_NGINX_HTML_DIR/nginx.sock")
        go("$TEST_NGINX_HTML_DIR/nginx.sock")
    }
--- stream_response
connected: 1, reused: 0
request sent: 61
received response of 119 bytes
connected: 1, reused: 1
request sent: 61
received response of 119 bytes
--- error_log eval
[
"lua tcp socket get keepalive peer: using connection",
'lua tcp socket keepalive create connection pool for key "unix:'
]
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for "
]



=== TEST 13: github issue #108: ngx.locaiton.capture + redis.set_keepalive
--- SKIP: ngx_http_lua only



=== TEST 14: github issue #110: ngx.exit with HTTP_NOT_FOUND causes worker process to exit
--- SKIP: ngx_http_lua only



=== TEST 15: custom pools (different pool for the same host:port) - tcp
--- stream_server_config
    content_by_lua_block {
        local function go(port, pool)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port, { pool = pool })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go($TEST_NGINX_MEMCACHED_PORT, "A")
        go($TEST_NGINX_MEMCACHED_PORT, "B")
    }
--- stream_response
connected: 1, reused: 0
connected: 1, reused: 0
--- error_log
lua tcp socket keepalive create connection pool for key "A"
lua tcp socket keepalive create connection pool for key "B"
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket get keepalive peer: using connection"
]



=== TEST 16: custom pools (same pool for different host:port) - tcp
--- stream_server_config
    content_by_lua_block {
        local function go(port, pool)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port, { pool = pool })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go($TEST_NGINX_MEMCACHED_PORT, "foo")
        go($TEST_NGINX_MEMCACHED_PORT, "foo")
    }
--- stream_response
connected: 1, reused: 0
connected: 1, reused: 1
--- error_log
lua tcp socket keepalive create connection pool for key "foo"
lua tcp socket get keepalive peer: using connection
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for ",
]



=== TEST 17: custom pools (different pool for the same host:port) - unix
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock;
        default_type 'text/plain';
        server_tokens off;

        location /foo {
            echo foo;
            more_clear_headers Date;
        }
    }
--- stream_server_config
    content_by_lua_block {
        local function go(pool)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock", { pool = pool })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go("A")
        go("B")
    }
--- stream_response
connected: 1, reused: 0
connected: 1, reused: 0
--- error_log
lua tcp socket keepalive create connection pool for key "A"
lua tcp socket keepalive create connection pool for key "B"
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket get keepalive peer: using connection"
]



=== TEST 18: custom pools (same pool for the same path) - unix
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock;
        default_type 'text/plain';
        server_tokens off;

        location /foo {
            echo foo;
            more_clear_headers Date;
        }
    }
--- stream_server_config
    content_by_lua_block {
        local function go(pool)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock", { pool = pool })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go("A")
        go("A")
    }
--- stream_response
connected: 1, reused: 0
connected: 1, reused: 1
--- error_log
lua tcp socket keepalive create connection pool for key "A"
lua tcp socket get keepalive peer: using connection
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for ",
]



=== TEST 19: numeric pool option value
--- stream_server_config
    content_by_lua_block {
        local function go(port, pool)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port, { pool = pool })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go($TEST_NGINX_MEMCACHED_PORT, 3.14)
        go($TEST_NGINX_SERVER_PORT, 3.14)
    }
--- stream_response
connected: 1, reused: 0
connected: 1, reused: 1
--- error_log
lua tcp socket keepalive create connection pool for key "3.14"
lua tcp socket get keepalive peer: using connection
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for ",
]



=== TEST 20: nil pool option value
--- stream_server_config
    content_by_lua_block {
        local function go(port, pool)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port, { pool = pool })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go($TEST_NGINX_MEMCACHED_PORT, nil)
        go($TEST_NGINX_SERVER_PORT, nil)
    }
--- stream_response
connected: 1, reused: 0
connected: 1, reused: 0
--- no_error_log
[error]



=== TEST 21: (bad) table pool option value
--- stream_server_config
    content_by_lua_block {
        local function go(port, pool)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port, { pool = pool })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go($TEST_NGINX_MEMCACHED_PORT, {})
        go($TEST_NGINX_SERVER_PORT, {})
    }
--- stream_response
--- error_log
bad argument #3 to 'connect' (bad "pool" option type: table)



=== TEST 22: (bad) boolean pool option value
--- stream_server_config
    content_by_lua_block {
        local function go(port, pool)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port, { pool = pool })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive()
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go($TEST_NGINX_MEMCACHED_PORT, true)
        go($TEST_NGINX_SERVER_PORT, false)
    }
--- stream_response
--- error_log
bad argument #3 to 'connect' (bad "pool" option type: boolean)



=== TEST 23: clear the redis store
--- SKIP: ngx_http_lua only



=== TEST 24: bug in send(): clear the chain writer ctx
--- SKIP
--- stream_server_config
    content_by_lua_block {
        local test = require "test"
        local port = ngx.var.port
        test.go($TEST_NGINX_REDIS_PORT)
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port)
    local sock = ngx.socket.tcp()
    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        ngx.say("failed to connect: ", err)
        return
    end

    local bytes, err = sock:send({})
    if err then
        ngx.say("failed to send empty request: ", err)
        return
    end

    local req = "*2\r\n$3\r\nget\r\n$3\r\ndog\r\n"

    local bytes, err = sock:send(req)
    if not bytes then
        ngx.say("failed to send request: ", err)
        return
    end

    local line, err, part = sock:receive()
    if line then
        ngx.say("received: ", line)

    else
        ngx.say("failed to receive a line: ", err, " [", part, "]")
    end

    local ok, err = sock:setkeepalive()
    if not ok then
        ngx.say("failed to set reusable: ", err)
    end

    ngx.say("done")
end
--- stap2
global active
M(stream-lua-socket-tcp-send-start) {
    active = 1
    printf("send [%s] %d\n", text_str(user_string_n($arg3, $arg4)), $arg4)
}
M(stream-lua-socket-tcp-receive-done) {
    printf("receive [%s]\n", text_str(user_string_n($arg3, $arg4)))
}
F(ngx_output_chain) {
    #printf("ctx->in: %s\n", ngx_chain_dump($ctx->in))
    #printf("ctx->busy: %s\n", ngx_chain_dump($ctx->busy))
    printf("output chain: %s\n", ngx_chain_dump($in))
}
F(ngx_linux_sendfile_chain) {
    printf("linux sendfile chain: %s\n", ngx_chain_dump($in))
}
F(ngx_chain_writer) {
    printf("chain writer ctx out: %p\n", $data)
    printf("nginx chain writer: %s\n", ngx_chain_dump($in))
}
F(ngx_stream_lua_socket_tcp_setkeepalive) {
    delete active
}
M(stream-lua-socket-tcp-setkeepalive-buf-unread) {
    printf("setkeepalive unread: [%s]\n", text_str(user_string_n($arg3, $arg4)))
}
probe syscall.recvfrom {
    if (active && pid() == target()) {
        printf("recvfrom(%s)", argstr)
    }
}
probe syscall.recvfrom.return {
    if (active && pid() == target()) {
        printf(" = %s, data [%s]\n", retstr, text_str(user_string_n($ubuf, $size)))
    }
}
probe syscall.writev {
    if (active && pid() == target()) {
        printf("writev(%s)", ngx_iovec_dump($vec, $vlen))
        /*
        for (i = 0; i < $vlen; i++) {
            printf(" %p [%s]", $vec[i]->iov_base, text_str(user_string_n($vec[i]->iov_base, $vec[i]->iov_len)))
        }
        */
    }
}
probe syscall.writev.return {
    if (active && pid() == target()) {
        printf(" = %s\n", retstr)
    }
}
--- stream_response
received: $-1
done
--- no_error_log
[error]



=== TEST 25: setkeepalive() with explicit nil args
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 100ms;
        echo foo;
    }
--- stream_server_config
    lua_socket_keepalive_timeout 100ms;

    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, res = reader()

        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive(nil, nil)
        if not ok then
            ngx.say("failed to set reusable: ", err)
        end

        ngx.sleep(1)

        ngx.say("done")
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
done
--- error_log eval
[
"lua tcp socket keepalive close handler",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket keepalive timeout: 100 ms",
qr/lua tcp socket connection pool size: 30\b/
]
--- no_error_log
[error]
--- timeout: 4



=== TEST 26: conn queuing: connect() verifies the options for connection pool
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()

        local function check_opts_for_connect(opts)
            local ok, err = pcall(function()
                sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT, opts)
            end)
            if not ok then
                ngx.say(err)
            else
                ngx.say("ok")
            end
        end

        check_opts_for_connect({pool_size = 'a'})
        check_opts_for_connect({pool_size = 0})
        check_opts_for_connect({backlog = -1})
        check_opts_for_connect({backlog = 0})
    }
--- stream_response_like
.+ 'connect' \(bad "pool_size" option type: string\)
.+ 'connect' \(bad "pool_size" option value: 0\)
.+ 'connect' \(bad "backlog" option value: -1\)
ok
--- no_error_log
[error]



=== TEST 27: conn queuing: connect() can specify 'pool_size' which overrides setkeepalive()
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT;

        local function go()
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port, { pool_size = 1 })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local req = "get __nil\r\n"
            local bytes, err = sock:send(req)
            if not bytes then
                ngx.say("failed to send request: ", err)
                return
            end
            ngx.say("request sent: ", bytes)

            local line, err, part = sock:receive()
            if line then
                ngx.say("received: ", line)
            else
                ngx.say("failed to receive a line: ", err, " [", part, "]")
            end

            local ok, err = sock:setkeepalive(0, 20)
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        -- reuse ok
        go()
        go()

        local sock1 = ngx.socket.connect("127.0.0.1", port)
        local sock2 = ngx.socket.connect("127.0.0.1", port)
        local ok, err = sock1:setkeepalive(0, 20)
        if not ok then
            ngx.say(err)
        end
        local ok, err = sock2:setkeepalive(0, 20)
        if not ok then
            ngx.say(err)
        end

        -- the pool_size is 1 instead of 20
        sock1 = ngx.socket.connect("127.0.0.1", port)
        sock2 = ngx.socket.connect("127.0.0.1", port)
        ngx.say("reused: ", sock1:getreusedtimes())
        ngx.say("reused: ", sock2:getreusedtimes())
        sock1:setkeepalive(0, 20)
        sock2:setkeepalive(0, 20)
    }
--- stream_response
connected: 1, reused: 0
request sent: 11
received: END
connected: 1, reused: 1
request sent: 11
received: END
reused: 1
reused: 0
--- error_log eval
[
qq{lua tcp socket keepalive create connection pool for key "127.0.0.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"},
"lua tcp socket connection pool size: 1",
]
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket connection pool size: 20"
]



=== TEST 28: conn queuing: connect() can specify 'pool_size' for unix domain socket
--- http_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    }
--- stream_server_config
    content_by_lua_block {
        local path = "unix:" .. "$TEST_NGINX_HTML_DIR/nginx.sock";

        local function go()
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect(path, { pool_size = 1 })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive(0, 20)
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go()
        go()

        local sock1 = ngx.socket.connect(path)
        local sock2 = ngx.socket.connect(path)
        local ok, err = sock1:setkeepalive(0, 20)
        if not ok then
            ngx.say(err)
        end
        local ok, err = sock2:setkeepalive(0, 20)
        if not ok then
            ngx.say(err)
        end

        -- the pool_size is 1 instead of 20
        sock1 = ngx.socket.connect(path)
        sock2 = ngx.socket.connect(path)
        ngx.say("reused: ", sock1:getreusedtimes())
        ngx.say("reused: ", sock2:getreusedtimes())
        sock1:setkeepalive(0, 20)
        sock2:setkeepalive(0, 20)
    }
--- stream_response
connected: 1, reused: 0
connected: 1, reused: 1
reused: 1
reused: 0
--- error_log eval
[
"lua tcp socket get keepalive peer: using connection",
'lua tcp socket keepalive create connection pool for key "unix:',
"lua tcp socket connection pool size: 1",
]
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket connection pool size: 20"
]



=== TEST 29: conn queuing: connect() can specify 'pool_size' for custom pool
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT

        local function go(pool)
            local sock = ngx.socket.tcp()
            sock:settimeouts(1000, 1000, 1000)

            local ok, err = sock:connect("127.0.0.1", port, {
                pool = pool,
                pool_size = 1
            })
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", pool, ", reused: ", sock:getreusedtimes())

            local ok, err = sock:setkeepalive(0, 20)
            if not ok then
                ngx.say("failed to set reusable: ", err)
            end
        end

        go("A")
        go("B")
        go("A")
        go("B")

        local sock1 = ngx.socket.connect("127.0.0.1", port, {pool = 'A'})
        local sock2 = ngx.socket.connect("127.0.0.1", port, {pool = 'A'})
        local ok, err = sock1:setkeepalive(0, 20)
        if not ok then
            ngx.say(err)
        end
        local ok, err = sock2:setkeepalive(0, 20)
        if not ok then
            ngx.say(err)
        end

        -- the pool_size is 1 instead of 20
        sock1 = ngx.socket.connect("127.0.0.1", port, {pool = 'A'})
        sock2 = ngx.socket.connect("127.0.0.1", port, {pool = 'A'})
        ngx.say("reused: ", sock1:getreusedtimes())
        ngx.say("reused: ", sock2:getreusedtimes())
        sock1:setkeepalive(0, 20)
        sock2:setkeepalive(0, 20)
    }
--- stream_response
connected: A, reused: 0
connected: B, reused: 0
connected: A, reused: 1
connected: B, reused: 1
reused: 1
reused: 0
--- no_error_log eval
[
"[error]",
"lua tcp socket keepalive: free connection pool for ",
"lua tcp socket connection pool size: 20"
]
--- error_log eval
[
qq{lua tcp socket keepalive create connection pool for key "A"},
qq{lua tcp socket keepalive create connection pool for key "B"},
"lua tcp socket connection pool size: 1"
]



=== TEST 30: conn queuing: connect() uses lua_socket_pool_size as default if 'backlog' is given
--- stream_server_config
    lua_socket_pool_size 1234;

    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local sock, err = ngx.socket.connect("127.0.0.1", port, { backlog = 0 })
        if not sock then
            ngx.say(err)
        else
            ngx.say("ok")
        end
    }
--- stream_response
ok
--- error_log
lua tcp socket connection pool size: 1234
--- no_error_log
[error]



=== TEST 31: conn queuing: more connect operations than 'backlog' size
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT

        local opts = {pool_size = 2, backlog = 0}
        local sock = ngx.socket.connect("127.0.0.1", port, opts)
        local not_reused_socket, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not not_reused_socket then
            ngx.say(err)
            return
        end
        -- burst
        local ok, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not ok then
            ngx.say(err)
        end

        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say(err)
            return
        end

        ok, err = sock:connect("127.0.0.1", port, opts)
        if not ok then
            ngx.say(err)
        end
        ngx.say("reused: ", sock:getreusedtimes())
        -- both queue and pool is full
        ok, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not ok then
            ngx.say(err)
        end
    }
--- stream_response
too many waiting connect operations
reused: 1
too many waiting connect operations
--- no_error_log
[error]



=== TEST 32: conn queuing: once 'pool_size' is reached and pool has 'backlog'
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool_size = 2, backlog = 2}
        local sock1 = ngx.socket.connect("127.0.0.1", port, opts)

        ngx.timer.at(0, function(premature)
            local sock2, err = ngx.socket.connect("127.0.0.1", port, opts)
            if not sock2 then
                ngx.log(ngx.ERR, err)
                return
            end

            ngx.log(ngx.WARN, "start to handle timer")
            ngx.sleep(0.1)
            sock2:close()
            -- resume connect operation
            ngx.log(ngx.WARN, "continue to handle timer")
        end)

        ngx.sleep(0.05)
        ngx.log(ngx.WARN, "start to handle cosocket")
        local sock3, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not sock3 then
            ngx.say(err)
            return
        end
        ngx.log(ngx.WARN, "continue to handle cosocket")

        local req = "get __nil\r\n"
        local bytes, err = sock3:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local line, err, part = sock3:receive()
        if line then
            ngx.say("received: ", line)
        else
            ngx.say("failed to receive a line: ", err, " [", part, "]")
        end

        local ok, err = sock3:setkeepalive()
        if not ok then
            ngx.say("failed to set reusable: ", err)
        end
        ngx.say("setkeepalive: OK")
    }
--- stream_response
request sent: 11
received: END
setkeepalive: OK
--- no_error_log
[error]
--- error_log
lua tcp socket queue connect operation for connection pool "127.0.0.1
--- grep_error_log eval: qr/(start|continue) to handle \w+/
--- grep_error_log_out
start to handle timer
start to handle cosocket
continue to handle timer
continue to handle cosocket



=== TEST 33: conn queuing: do not count failed connect operations
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;

    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool = "test", pool_size = 1, backlog = 0}

        local sock = ngx.socket.tcp()
        sock:settimeouts(100, 3000, 3000)
        local ok, err = sock:connect("127.0.0.2", 12345, opts)
        if not ok then
            ngx.say(err)
        end

        local sock, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not sock then
            ngx.say(err)
        end
        ngx.say("ok")
    }
--- error_log
stream lua tcp socket connect timed out, upstream: 127.0.0.2:12345(127.0.0.2)
--- stream_response
timeout
ok



=== TEST 34: conn queuing: connect until backlog is reached
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool_size = 1, backlog = 1}
        local sock1 = ngx.socket.connect("127.0.0.1", port, opts)

        ngx.timer.at(0.01, function(premature)
            ngx.log(ngx.WARN, "start to handle timer")
            local sock2, err = ngx.socket.connect("127.0.0.1", port, opts)
            if not sock2 then
                ngx.log(ngx.ERR, err)
                return
            end

            ngx.sleep(0.02)
            local ok, err = sock2:close()
            if not ok then
                ngx.log(ngx.ERR, err)
            end
            ngx.log(ngx.WARN, "continue to handle timer")
        end)

        ngx.sleep(0.02)
        local sock3, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not sock3 then
            ngx.say(err)
        end
        local ok, err = sock1:setkeepalive()
        if not ok then
            ngx.say(err)
            return
        end
        ngx.sleep(0.01) -- run sock2

        ngx.log(ngx.WARN, "start to handle cosocket")
        local sock3, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not sock3 then
            ngx.say(err)
            return
        end
        ngx.log(ngx.WARN, "continue to handle cosocket")

        local ok, err = sock3:setkeepalive()
        if not ok then
            ngx.say(err)
        end
    }
--- stream_response
too many waiting connect operations
--- error_log
lua tcp socket queue connect operation for connection pool "127.0.0.1
--- no_error_log
[error]
--- grep_error_log eval: qr/queue connect operation for connection pool|(start|continue) to handle \w+/
--- grep_error_log_out
start to handle timer
queue connect operation for connection pool
start to handle cosocket
queue connect operation for connection pool
continue to handle timer
continue to handle cosocket



=== TEST 35: conn queuing: memory reuse for host in queueing connect operation ctx
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool = "test", pool_size = 1, backlog = 3}
        local sock = ngx.socket.connect("127.0.0.1", port, opts)

        ngx.timer.at(0.01, function(premature)
            local sock, err = ngx.socket.connect("0.0.0.0", port, opts)
            if not sock then
                ngx.log(ngx.ERR, err)
                return
            end

            local ok, err = sock:close()
            if not ok then
                ngx.log(ngx.ERR, err)
            end
        end)

        ngx.timer.at(0.015, function(premature)
            local sock, err = ngx.socket.connect("127.0.0.1", port, opts)
            if not sock then
                ngx.log(ngx.ERR, err)
                return
            end

            local ok, err = sock:close()
            if not ok then
                ngx.log(ngx.ERR, err)
            end
        end)

        ngx.timer.at(0.02, function(premature)
            local sock, err = ngx.socket.connect("0.0.0.0", port, opts)
            if not sock then
                ngx.log(ngx.ERR, err)
                return
            end

            local ok, err = sock:close()
            if not ok then
                ngx.log(ngx.ERR, err)
            end
        end)

        ngx.sleep(0.03)
        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say(err)
            return
        end
        ngx.say("ok")
    }
--- stream_response
ok
--- grep_error_log eval: qr/queue connect operation for connection pool/
--- grep_error_log_out
queue connect operation for connection pool
queue connect operation for connection pool
queue connect operation for connection pool
--- no_error_log
[error]



=== TEST 36: conn queuing: connect() returns error after connect operation resumed
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool = "test", pool_size = 1, backlog = 1}
        local sock = ngx.socket.connect("127.0.0.1", port, opts)

        ngx.timer.at(0, function(premature)
            local sock, err = ngx.socket.connect("", port, opts)
            if not sock then
                ngx.log(ngx.WARN, err)
            end
        end)

        ngx.sleep(0.01)
        -- use 'close' to force parsing host instead of reusing conn
        local ok, err = sock:close()
        if not ok then
            ngx.say(err)
            return
        end
        ngx.say("ok")
    }
--- stream_response
ok
--- error_log
failed to parse host name
--- no_error_log
[error]
--- grep_error_log eval: qr/queue connect operation for connection pool/
--- grep_error_log_out
queue connect operation for connection pool



=== TEST 37: conn queuing: in uthread
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool_size = 1, backlog = 2}

        local conn_sock = function()
            local sock, err = ngx.socket.connect("127.0.0.1", port, opts)
            if not sock then
                ngx.say(err)
                return
            end
            ngx.say("start to handle uthread")

            ngx.sleep(0.01)
            sock:close()
            ngx.say("continue to handle other uthread")
        end

        local sock, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not sock then
            ngx.log(ngx.ERR, err)
            return
        end

        local co1 = ngx.thread.spawn(conn_sock)
        local co2 = ngx.thread.spawn(conn_sock)
        local co3 = ngx.thread.spawn(conn_sock)

        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.log(ngx.ERR, err)
        end

        ngx.thread.wait(co1)
        ngx.thread.wait(co2)
        ngx.thread.wait(co3)
        ngx.say("all uthreads ok")
    }
--- stream_response
too many waiting connect operations
start to handle uthread
continue to handle other uthread
start to handle uthread
continue to handle other uthread
all uthreads ok
--- no_error_log
[error]
--- grep_error_log eval: qr/queue connect operation for connection pool/
--- grep_error_log_out
queue connect operation for connection pool
queue connect operation for connection pool



=== TEST 38: conn queuing: in access_by_lua
--- SKIP: ngx_http_lua only



=== TEST 39: conn queuing: in rewrite_by_lua
--- SKIP: ngx_http_lua only



=== TEST 40: conn queuing: in subrequest
--- SKIP: ngx_http_lua only



=== TEST 41: conn queuing: timeouts when 'connect_timeout' is reached
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool_size = 1, backlog = 1}
        local sock1 = ngx.socket.connect("127.0.0.1", port, opts)

        local sock2 = ngx.socket.tcp()
        sock2:settimeouts(100, 3000, 3000)
        local ok, err = sock2:connect("127.0.0.1", port, opts)
        if not ok then
            ngx.say(err)
        end
    }
--- stream_response
timeout
--- error_log eval
"lua tcp socket queued connect timed out, when trying to connect to 127.0.0.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"



=== TEST 42: conn queuing: set timeout via lua_socket_connect_timeout
--- stream_server_config
    lua_socket_connect_timeout 100ms;

    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool_size = 1, backlog = 1}
        local sock1 = ngx.socket.connect("127.0.0.1", port, opts)

        local sock2 = ngx.socket.tcp()
        local ok, err = sock2:connect("127.0.0.1", port, opts)
        if not ok then
            ngx.say(err)
        end
    }
--- stream_response
timeout
--- error_log eval
"lua tcp socket queued connect timed out, when trying to connect to 127.0.0.1:$ENV{TEST_NGINX_MEMCACHED_PORT}"



=== TEST 43: conn queuing: client aborting while connect operation is queued
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool_size = 1, backlog = 1}
        local sock1 = ngx.socket.connect("127.0.0.1", port, opts)

        local sock2 = ngx.socket.tcp()
        sock2:settimeouts(3000, 3000, 3000)
        local ok, err = sock2:connect("127.0.0.1", port, opts)
        if not ok then
            ngx.say(err)
        end
    }
--- ignore_stream_response
--- timeout: 0.1
--- abort
--- no_error_log
[error]



=== TEST 44: conn queuing: resume next connect operation if resumed connect failed immediately
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool = "test", pool_size = 1, backlog = 2}

        local conn_sock = function(should_timeout)
            local sock = ngx.socket.tcp()
            local ok, err
            if should_timeout then
                ok, err = sock:connect("", port, opts)
            else
                ok, err = sock:connect("127.0.0.1", port, opts)
            end
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("connected in uthread")
            sock:close()
        end

        local sock, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not sock then
            ngx.log(ngx.ERR, err)
            return
        end

        local co1 = ngx.thread.spawn(conn_sock, true)
        local co2 = ngx.thread.spawn(conn_sock)

        local ok, err = sock:close()
        if not ok then
            ngx.log(ngx.ERR, err)
        end

        ngx.thread.wait(co1)
        ngx.thread.wait(co2)
        ngx.say("ok")
    }
--- stream_response
failed to parse host name "": no host
connected in uthread
ok
--- no_error_log
[error]



=== TEST 45: conn queuing: resume connect operation if resumed connect failed (timeout)
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;

    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool = "test", pool_size = 1, backlog = 1}

        local conn_sock = function(should_timeout)
            local sock = ngx.socket.tcp()
            local ok, err
            if should_timeout then
                sock:settimeouts(100, 3000, 3000)
                ok, err = sock:connect("127.0.0.2", 12345, opts)
            else
                ok, err = sock:connect("127.0.0.1", port, opts)
            end
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("connected in uthread")
            sock:close()
        end

        local co1 = ngx.thread.spawn(conn_sock, true)
        local co2 = ngx.thread.spawn(conn_sock)

        ngx.thread.wait(co1)
        ngx.thread.wait(co2)
        ngx.say("ok")
    }
--- stream_response
timeout
connected in uthread
ok
--- error_log
queue connect operation for connection pool "test"
stream lua tcp socket connect timed out, upstream: 127.0.0.2:12345(127.0.0.2)



=== TEST 46: conn queuing: resume connect operation if resumed connect failed (could not be resolved)
--- stream_server_config
    resolver 127.0.0.2:12345 ipv6=off;
    resolver_timeout 1s;

    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool = "test", pool_size = 1, backlog = 1}

        local conn_sock = function(should_timeout)
            local sock = ngx.socket.tcp()
            local ok, err
            if should_timeout then
                sock:settimeouts(1, 3000, 3000)
                ok, err = sock:connect("agentzh.org", 80, opts)
            else
                ok, err = sock:connect("127.0.0.1", port, opts)
            end
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("connected in uthread")
            sock:close()
        end

        local co1 = ngx.thread.spawn(conn_sock, true)
        local co2 = ngx.thread.spawn(conn_sock)

        ngx.thread.wait(co1)
        ngx.thread.wait(co2)
        ngx.say("ok")
    }
--- stream_response
agentzh.org could not be resolved (110: Operation timed out)
connected in uthread
ok
--- error_log
queue connect operation for connection pool "test"



=== TEST 47: conn queuing: resume connect operation if resumed connect failed (connection refused)
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool = "test", pool_size = 1, backlog = 1}

        local conn_sock = function(should_timeout)
            local sock = ngx.socket.tcp()
            local ok, err
            if should_timeout then
                sock:settimeouts(100, 3000, 3000)
                ok, err = sock:connect("127.0.0.1", 62345, opts)
            else
                ok, err = sock:connect("127.0.0.1", port, opts)
            end
            if not ok then
                ngx.say(err)
                return
            end
            ngx.say("connected in uthread")
            sock:close()
        end

        local co1 = ngx.thread.spawn(conn_sock, true)
        local co2 = ngx.thread.spawn(conn_sock)

        ngx.thread.wait(co1)
        ngx.thread.wait(co2)
        ngx.say("ok")
    }
--- stream_response
connection refused
connected in uthread
ok
--- error_log
queue connect operation for connection pool "test"



=== TEST 48: conn queuing: resume connect operation if resumed connect failed (uthread aborted while resolving)
--- stream_server_config
    resolver 127.0.0.1 ipv6=off;
    resolver_timeout 100s;

    content_by_lua_block {
        local function sub()
            local semaphore = require "ngx.semaphore"
            local sem = semaphore.new()

            local function f()
                sem:wait(0.1)
                ngx.exit(0)
            end

            local port = $TEST_NGINX_MEMCACHED_PORT
            local opts = {pool = "test", pool_size = 1, backlog = 1}

            ngx.timer.at(0, function()
                sem:post()
                local sock2, err = ngx.socket.connect("127.0.0.1", port, opts)
                package.loaded.for_timer_to_resume:post()
                if not sock2 then
                    ngx.log(ngx.ALERT, "resume connect failed: ", err)
                    return
                end

                ngx.log(ngx.INFO, "resume success")
            end)

            ngx.thread.spawn(f)
            local sock1, err = ngx.socket.connect("openresty.org", 80, opts)
            if not sock1 then
                ngx.say(err)
                return
            end
        end

        local function t()
            local semaphore = require "ngx.semaphore"
            local for_timer_to_resume = semaphore.new()
            package.loaded.for_timer_to_resume = for_timer_to_resume

            ngx.thread.spawn(sub)
            for_timer_to_resume:wait(0.1)
        end

        t()
    }
--- no_error_log
[alert]
--- error_log
resume success



=== TEST 49: conn queuing: resume connect operation if resumed connect failed (uthread killed while resolving)
--- stream_server_config
    resolver 127.0.0.1 ipv6=off;
    resolver_timeout 100s;

    content_by_lua_block {
        local opts = {pool = "test", pool_size = 1, backlog = 1}
        local port = $TEST_NGINX_MEMCACHED_PORT

        local function resolve()
            local sock1, err = ngx.socket.connect("openresty.org", 80, opts)
            if not sock1 then
                ngx.say(err)
                return
            end
        end

        local th = ngx.thread.spawn(resolve)
        local ok, err = ngx.thread.kill(th)
        if not ok then
            ngx.log(ngx.ALERT, "kill thread failed: ", err)
            return
        end

        local sock2, err = ngx.socket.connect("127.0.0.1", port, opts)
        if not sock2 then
            ngx.log(ngx.ALERT, "resume connect failed: ", err)
            return
        end

        ngx.log(ngx.INFO, "resume success")
    }
--- no_error_log
[alert]
--- error_log
resume success



=== TEST 50: conn queuing: increase the counter for connections created before creating the pool with setkeepalive()
--- stream_server_config
    content_by_lua_block {
        local function connect()
            local sock, err = ngx.socket.connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
            if not sock then
                error("connect failed: " .. err)
            end

            return sock
        end

        local sock1 = connect()
        local sock2 = connect()
        assert(sock1:setkeepalive())
        assert(sock2:setkeepalive())

        local sock1 = connect()
        local sock2 = connect()
        assert(sock1:close())
        assert(sock2:close())

        ngx.say("ok")
    }
--- stream_response
ok
--- no_error_log
[error]



=== TEST 51: conn queuing: only decrease the counter for connections which were counted by the pool
--- stream_server_config
    content_by_lua_block {
        local function connect()
            local sock, err = ngx.socket.connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT)
            if not sock then
                error("connect failed: " .. err)
            end

            return sock
        end

        local sock1 = connect()
        local sock2 = connect()
        assert(sock1:setkeepalive(1000, 1))
        assert(sock2:setkeepalive(1000, 1))

        local sock1 = connect()
        local sock2 = connect()
        assert(sock1:close())
        assert(sock2:close())

        ngx.say("ok")
    }
--- stream_response
ok
--- no_error_log
[error]



=== TEST 52: conn queuing: clean up pending connect operations which are in queue
--- stream_server_config
    content_by_lua_block {
        local function sub()
            local opts = {pool = "test", pool_size = 1, backlog = 1}
            local sock, err = ngx.socket.connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT, opts)
            if not sock then
                ngx.say("connect failed: " .. err)
                return
            end

            local function f()
                assert(ngx.socket.connect("127.0.0.1", $TEST_NGINX_MEMCACHED_PORT, opts))
            end

            local th = ngx.thread.spawn(f)
            local ok, err = ngx.thread.kill(th)
            if not ok then
                ngx.log(ngx.ERR, "kill thread failed: ", err)
                return
            end

            sock:close()
        end

        local function t()
            ngx.thread.spawn(sub)
            -- let pending connect operation resumes first
            ngx.sleep(0)
            ngx.say("ok")
        end

        t()
    }
--- stream_response
ok
--- error_log
lua tcp socket abort queueing
--- no_error_log
[error]



=== TEST 53: wrong first argument of setkeepalive()
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 60s;
        echo foo;
    }
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local ok, err = sock:setkeepalive("not a number")
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
--- error_log eval
qr/\Qbad argument #1 to 'setkeepalive' (number expected, got string)\E/
--- no_error_log 
[crit]
--- timeout: 4



=== TEST 54: wrong second argument of setkeepalive()
--- config
    location /foo {
        server_tokens off;
        keepalive_timeout 60s;
        echo foo;
    }
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeouts(1000, 1000, 1000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.1\r\nHost: localhost\r\nConnection: keepalive\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local reader = sock:receiveuntil("\r\n0\r\n\r\n")
        local data, err = reader()
        if not data then
            ngx.say("failed to receive response body: ", err)
            return
        end

        ngx.say("received response of ", #data, " bytes")

        local ok, err = sock:setkeepalive()
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end

        ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local ok, err = sock:setkeepalive(10, "not a number")
        if not ok then
            ngx.say("failed to set reusable: ", err)
            return
        end
    }
--- stream_response
connected: 1
request sent: 61
received response of 156 bytes
--- error_log eval
qr/\Qbad argument #2 to 'setkeepalive' (number expected, got string)\E/
--- no_error_log 
[crit]
--- timeout: 4



=== TEST 55: conn queuing: slots freed in the same cycle each resume a queued connect
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT
        local opts = {pool = "same_cycle", pool_size = 2, backlog = 2}

        local sock1 = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local sock2 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter(name)
            return ngx.thread.spawn(function()
                local sock = ngx.socket.tcp()
                sock:settimeouts(500, 500, 500)

                local ok, err = sock:connect("127.0.0.1", port, opts)
                if not ok then
                    return name .. ": " .. err
                end

                -- keep the slot past the other waiter's connect timeout,
                -- so only a resumption can let it connect
                ngx.sleep(1)
                sock:close()
                return name .. ": connected"
            end)
        end

        local w1 = waiter("w1")
        local w2 = waiter("w2")

        -- release both connections in the same cycle
        assert(sock1:setkeepalive())
        assert(sock2:setkeepalive())

        local _, res1 = ngx.thread.wait(w1)
        local _, res2 = ngx.thread.wait(w2)
        ngx.say(res1)
        ngx.say(res2)
    }
--- stream_response
w1: connected
w2: connected
--- error_log
stream lua tcp socket queue connect operation for connection pool "same_cycle"
--- no_error_log
[error]
--- timeout: 4



=== TEST 56: conn queuing: close multiple connections before resumptions run
--- stream_server_config
    content_by_lua_block {
        local semaphore = require "ngx.semaphore"
        local connected = semaphore.new()
        local release = semaphore.new()
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "same_cycle_close", pool_size = 2, backlog = 2}

        local sock1 = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local sock2 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter(name)
            local sock = ngx.socket.tcp()
            sock:settimeout(500)
            assert(sock:connect("127.0.0.1", port, opts))
            local reused = sock:getreusedtimes()
            connected:post()
            assert(release:wait(2))
            sock:close()
            return name .. ": reused " .. reused
        end

        local w1 = ngx.thread.spawn(waiter, "w1")
        local w2 = ngx.thread.spawn(waiter, "w2")

        assert(sock1:close())
        assert(sock2:close())

        -- neither waiter may free its slot before both have connected
        assert(connected:wait(2))
        assert(connected:wait(2))
        release:post(2)

        local _, res1 = ngx.thread.wait(w1)
        local _, res2 = ngx.thread.wait(w2)
        ngx.say(res1)
        ngx.say(res2)
    }
--- stream_response
w1: reused 0
w2: reused 0
--- error_log
stream lua tcp socket queue connect operation for connection pool "same_cycle_close"
--- no_error_log
[error]
--- timeout: 4



=== TEST 57: conn queuing: cancel a posted resumption and resume the next waiter
--- stream_server_config
    content_by_lua_block {
        local semaphore = require "ngx.semaphore"
        local connected = semaphore.new()
        local release = semaphore.new()
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "cancel_posted", pool_size = 2, backlog = 3}
        local order = {}

        local sock1 = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local sock2 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter(name)
            local sock = ngx.socket.tcp()
            sock:settimeout(500)
            assert(sock:connect("127.0.0.1", port, opts))
            order[#order + 1] = name
            local reused = sock:getreusedtimes()
            connected:post()
            assert(release:wait(2))
            sock:close()
            return name .. ": reused " .. reused
        end

        local w1 = ngx.thread.spawn(waiter, "w1")
        local w2 = ngx.thread.spawn(waiter, "w2")
        local w3 = ngx.thread.spawn(waiter, "w3")

        assert(sock1:setkeepalive())
        assert(sock2:setkeepalive())
        assert(ngx.thread.kill(w1))

        assert(connected:wait(2))
        assert(connected:wait(2))
        release:post(2)

        local _, res2 = ngx.thread.wait(w2)
        local _, res3 = ngx.thread.wait(w3)
        ngx.say(res2)
        ngx.say(res3)
        ngx.say("order: ", table.concat(order, ", "))
    }
--- stream_response
w2: reused 1
w3: reused 1
order: w2, w3
--- error_log
stream lua tcp socket abort queueing
--- no_error_log
[error]
--- timeout: 4



=== TEST 58: conn queuing: advance past a timed out waiter
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local semaphore = require "ngx.semaphore"
        local expired = semaphore.new()
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "expired_head", pool_size = 1, backlog = 2}
        local sock = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter1()
            local s = ngx.socket.tcp()
            s:settimeout(10)
            local ok, err = s:connect("127.0.0.1", port, opts)
            expired:post()
            return "w1: " .. (err or "connected")
        end

        local function waiter2()
            local s = ngx.socket.tcp()
            s:settimeout(500)
            assert(s:connect("127.0.0.1", port, opts))
            local reused = s:getreusedtimes()
            s:close()
            return "w2: reused " .. reused
        end

        local w1 = ngx.thread.spawn(waiter1)
        local w2 = ngx.thread.spawn(waiter2)
        assert(expired:wait(2))
        assert(sock:setkeepalive())

        local _, res1 = ngx.thread.wait(w1)
        local _, res2 = ngx.thread.wait(w2)
        ngx.say(res1)
        ngx.say(res2)
    }
--- stream_response
w1: timeout
w2: reused 1
--- error_log
stream lua tcp socket queue connect operation for connection pool "expired_head"
--- no_error_log
[error]
--- timeout: 4



=== TEST 59: conn queuing: append after all existing waiters have been posted
--- stream_server_config
    content_by_lua_block {
        local semaphore = require "ngx.semaphore"
        local connected = semaphore.new()
        local release = semaphore.new()
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "append_posted", pool_size = 1, backlog = 2}
        local sock = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter1()
            local s = ngx.socket.tcp()
            s:settimeout(500)
            assert(s:connect("127.0.0.1", port, opts))
            connected:post()
            assert(release:wait(2))
            s:close()
            return "w1: connected"
        end

        local function waiter2()
            local s = ngx.socket.tcp()
            s:settimeout(500)
            assert(s:connect("127.0.0.1", port, opts))
            s:close()
            return "w2: connected"
        end

        local w1 = ngx.thread.spawn(waiter1)
        assert(sock:close())
        local w2 = ngx.thread.spawn(waiter2)

        assert(connected:wait(2))
        release:post()
        local _, res1 = ngx.thread.wait(w1)
        local _, res2 = ngx.thread.wait(w2)
        ngx.say(res1)
        ngx.say(res2)
    }
--- stream_response
w1: connected
w2: connected
--- error_log
stream lua tcp socket queue connect operation for connection pool "append_posted"
--- no_error_log
[error]
--- timeout: 4



=== TEST 60: conn queuing: a new connect does not take the idle connection handed to a queued one
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "queue_jump", pool_size = 1, backlog = 2}
        local sock1 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        -- queued behind sock1, the only slot
        local waiter = ngx.thread.spawn(function()
            local s = ngx.socket.tcp()
            s:settimeout(1000)
            assert(s:connect("127.0.0.1", port, opts))
            local reused = s:getreusedtimes()
            assert(s:setkeepalive())
            return "waiter: reused " .. reused
        end)

        -- hand the slot to the waiter, whose resumption is only posted
        assert(sock1:setkeepalive())

        -- a connect in the same cycle must queue behind the waiter: taking
        -- the idle connection would make the waiter open a second one
        local sock3 = ngx.socket.tcp()
        sock3:settimeout(1000)
        assert(sock3:connect("127.0.0.1", port, opts))
        local reused = sock3:getreusedtimes()
        sock3:close()

        local _, res = ngx.thread.wait(waiter)
        ngx.say(res)
        ngx.say("newcomer: reused ", reused)
    }
--- stream_response
waiter: reused 1
newcomer: reused 2
--- error_log
stream lua tcp socket queue connect operation for connection pool "queue_jump"
--- no_error_log
[error]



=== TEST 61: conn queuing: a new connect reuses an idle connection no queued one was resumed for
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "spare_idle", pool_size = 2, backlog = 2}
        local sock1 = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local sock2 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        -- queued behind sock1 and sock2
        local waiter = ngx.thread.spawn(function()
            local s = ngx.socket.tcp()
            s:settimeout(1000)
            assert(s:connect("127.0.0.1", port, opts))
            local reused = s:getreusedtimes()
            -- hold the connection past the newcomer's connect timeout
            ngx.sleep(0.5)
            assert(s:setkeepalive())
            return "waiter: reused " .. reused
        end)

        -- two connections come back, one of them is handed to the waiter
        assert(sock1:setkeepalive())
        assert(sock2:setkeepalive())

        -- the other one is free to reuse: queuing behind the waiter would
        -- time out while it sits idle
        local sock3 = ngx.socket.tcp()
        sock3:settimeout(200)
        local ok, err = sock3:connect("127.0.0.1", port, opts)
        local res = ok and "newcomer: reused " .. sock3:getreusedtimes()
                    or "newcomer: " .. err
        if ok then
            sock3:close()
        end

        local _, wres = ngx.thread.wait(waiter)
        ngx.say(wres)
        ngx.say(res)
    }
--- stream_response
waiter: reused 1
newcomer: reused 1
--- error_log
stream lua tcp socket queue connect operation for connection pool "spare_idle"
--- no_error_log
[error]
--- timeout: 4



=== TEST 62: conn queuing: a cancelled resumed connect passes its idle connection to the next one
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "pass_reserved", pool_size = 1, backlog = 3}
        local sock1 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter(name)
            return ngx.thread.spawn(function()
                local s = ngx.socket.tcp()
                s:settimeout(1000)
                assert(s:connect("127.0.0.1", port, opts))
                local reused = s:getreusedtimes()
                assert(s:setkeepalive())
                return name .. ": reused " .. reused
            end)
        end

        local w1 = waiter("w1")
        local w2 = waiter("w2")

        -- hand the only connection to w1, then cancel w1 before it runs
        assert(sock1:setkeepalive())
        assert(ngx.thread.kill(w1))

        -- the connection now belongs to w2, not to a new connect
        local sock3 = ngx.socket.tcp()
        sock3:settimeout(1000)
        assert(sock3:connect("127.0.0.1", port, opts))
        local reused = sock3:getreusedtimes()
        sock3:close()

        local _, res = ngx.thread.wait(w2)
        ngx.say(res)
        ngx.say("newcomer: reused ", reused)
    }
--- stream_response
w2: reused 1
newcomer: reused 2
--- error_log
stream lua tcp socket queue connect operation for connection pool "pass_reserved"
--- no_error_log
[error]



=== TEST 63: conn queuing: cancelling a queued connect frees no slot
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "cancel_queued", pool_size = 1, backlog = 2}
        local sock1 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter(name)
            return ngx.thread.spawn(function()
                local s = ngx.socket.tcp()
                s:settimeout(300)
                local ok, err = s:connect("127.0.0.1", port, opts)
                if not ok then
                    return name .. ": " .. err
                end
                local reused = s:getreusedtimes()
                s:close()
                return name .. ": reused " .. reused
            end)
        end

        local w1 = waiter("w1")
        local w2 = waiter("w2")

        -- w1 never got a slot: cancelling it must not let w2 connect while
        -- sock1 still holds the only one
        assert(ngx.thread.kill(w1))

        local _, res = ngx.thread.wait(w2)
        ngx.say(res)
        sock1:close()
    }
--- stream_response
w2: timeout
--- error_log
stream lua tcp socket queue connect operation for connection pool "cancel_queued"
--- no_error_log
[alert]



=== TEST 64: conn queuing: a resumed connect cancelled after its idle connection closed hands the slot on
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "reserved_closed", pool_size = 1, backlog = 2}
        local sock1 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter(name)
            return ngx.thread.spawn(function()
                local s = ngx.socket.tcp()
                s:settimeout(500)
                local ok, err = s:connect("127.0.0.1", port, opts)
                if not ok then
                    return name .. ": " .. err
                end
                local reused = s:getreusedtimes()
                s:close()
                return name .. ": reused " .. reused
            end)
        end

        local w1 = waiter("w1")
        local w2 = waiter("w2")

        -- runs once this thread sleeps below: its 1ms keepalive timer
        -- is then ahead of the sleep timer, and both expire in this
        -- cycle before w1's posted resumption runs
        local spinner = ngx.thread.spawn(function()
            coroutine.yield()

            -- hand the only connection to w1, to be closed before w1 runs
            assert(sock1:setkeepalive(1))

            local t = ngx.now()
            repeat
                ngx.update_time()
            until ngx.now() - t >= 0.005
        end)

        -- wakes up after the reserved connection closed, to cancel w1
        ngx.sleep(0.002)
        local killed, err = ngx.thread.kill(w1)
        ngx.thread.wait(spinner)

        local _, res = ngx.thread.wait(w2)
        ngx.say("killed: ", killed or err)
        ngx.say(res)
    }
--- stream_response
killed: 1
w2: reused 0
--- error_log
stream lua tcp socket queue connect operation for connection pool "reserved_closed"
--- no_error_log
[error]



=== TEST 65: conn queuing: a pre-pool connection cannot replace an assigned connection
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local pool = "replace_reserved"
        local legacy = assert(ngx.socket.connect("127.0.0.1", port,
                                                {pool = pool}))
        local opts = {pool = pool, pool_size = 1, backlog = 2}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        assert(holder:setkeepalive())
        holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local waiter = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            assert(sock:connect("127.0.0.1", port, opts))
            local reused = sock:getreusedtimes()
            assert(sock:setkeepalive())
            return "waiter: reused " .. reused
        end)

        -- The already reused connection belongs to the posted waiter;
        -- a pre-pool connection must not replace it or take its slot.
        assert(holder:setkeepalive())
        assert(legacy:setkeepalive())

        local newcomer = ngx.socket.tcp()
        newcomer:settimeout(1000)
        assert(newcomer:connect("127.0.0.1", port, opts))
        local reused = newcomer:getreusedtimes()
        local ok, res = ngx.thread.wait(waiter)
        assert(ok, res)

        -- Hold the newcomer open: there must be no second live connection
        -- available in this pool of size one.
        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local connected, err = extra:connect("127.0.0.1", port, opts)
        ngx.say(res)
        ngx.say("newcomer: reused ", reused)
        ngx.say("extra: ", connected or err)
        if connected then
            extra:close()
        end

        newcomer:close()
    }
--- stream_response
waiter: reused 2
newcomer: reused 3
extra: timeout
--- error_log
lua tcp socket queue connect operation for connection pool "replace_reserved"
--- no_error_log
[error]



=== TEST 66: conn queuing: a pre-pool connection cannot wake another waiter after handoff
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local semaphore = require "ngx.semaphore"
        local connected = semaphore.new()
        local release = semaphore.new()
        local port = $TEST_NGINX_SERVER_PORT
        local pool = "replace_reserved_waiters"
        local legacy = assert(ngx.socket.connect("127.0.0.1", port,
                                                {pool = pool}))
        local opts = {pool = pool, pool_size = 1, backlog = 2}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        assert(holder:setkeepalive())
        holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local w1 = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            assert(sock:connect("127.0.0.1", port, opts))
            local reused = sock:getreusedtimes()
            connected:post()
            assert(release:wait(2))
            sock:close()
            return "w1: reused " .. reused
        end)

        local w2 = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(100)
            local ok, err = sock:connect("127.0.0.1", port, opts)
            if not ok then
                return "w2: " .. err
            end

            local reused = sock:getreusedtimes()
            sock:close()
            return "w2: reused " .. reused
        end)

        -- Returning a pre-pool connection must neither replace w1's
        -- assigned connection nor resume w2 for the same slot.
        assert(holder:setkeepalive())
        assert(legacy:setkeepalive())
        assert(connected:wait(2))

        local ok, res2 = ngx.thread.wait(w2)
        assert(ok, res2)
        release:post()
        local ok, res1 = ngx.thread.wait(w1)
        assert(ok, res1)
        ngx.say(res1)
        ngx.say(res2)
    }
--- stream_response
w1: reused 2
w2: timeout
--- error_log
lua tcp socket queue connect operation for connection pool "replace_reserved_waiters"
--- no_error_log
[error]
--- timeout: 4



=== TEST 67: conn queuing: a pre-pool connection cannot take a posted slot
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local pool = "legacy_posted_slot"
        local legacy = assert(ngx.socket.connect("127.0.0.1", port,
                                                {pool = pool}))
        local opts = {pool = pool, pool_size = 1, backlog = 2}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local waiter = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            assert(sock:connect("127.0.0.1", port, opts))
            local reused = sock:getreusedtimes()
            assert(sock:setkeepalive())
            return "waiter: reused " .. reused
        end)

        -- The freed slot belongs to the posted waiter. The uncounted
        -- legacy connection must be closed rather than added to cache.
        assert(holder:close())
        assert(legacy:setkeepalive())

        local newcomer = ngx.socket.tcp()
        newcomer:settimeout(1000)
        assert(newcomer:connect("127.0.0.1", port, opts))
        local reused = newcomer:getreusedtimes()
        local ok, res = ngx.thread.wait(waiter)
        assert(ok, res)

        -- Hold the newcomer open: there must be no second live connection
        -- available in this pool of size one.
        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local connected, err = extra:connect("127.0.0.1", port, opts)
        ngx.say(res)
        ngx.say("newcomer: reused ", reused)
        ngx.say("extra: ", connected or err)
        if connected then
            extra:close()
        end

        newcomer:close()
    }
--- stream_response
waiter: reused 0
newcomer: reused 1
extra: timeout
--- error_log
lua tcp socket queue connect operation for connection pool "legacy_posted_slot"
--- no_error_log
[error]



=== TEST 68: conn queuing: a pre-pool connection frees no second posted slot
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local semaphore = require "ngx.semaphore"
        local connected = semaphore.new()
        local release = semaphore.new()
        local port = $TEST_NGINX_SERVER_PORT
        local pool = "legacy_posted_waiters"
        local legacy = assert(ngx.socket.connect("127.0.0.1", port,
                                                {pool = pool}))
        local opts = {pool = pool, pool_size = 1, backlog = 2}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local w1 = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            assert(sock:connect("127.0.0.1", port, opts))
            local reused = sock:getreusedtimes()
            connected:post()
            assert(release:wait(2))
            sock:close()
            return "w1: reused " .. reused
        end)

        local w2 = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(100)
            local ok, err = sock:connect("127.0.0.1", port, opts)
            if not ok then
                return "w2: " .. err
            end

            local reused = sock:getreusedtimes()
            sock:close()
            return "w2: reused " .. reused
        end)

        -- The close hands the only slot to w1. Returning an uncounted
        -- connection must not also resume w2 for that same slot.
        assert(holder:close())
        assert(legacy:setkeepalive())
        assert(connected:wait(2))

        local ok, res2 = ngx.thread.wait(w2)
        assert(ok, res2)
        release:post()
        local ok, res1 = ngx.thread.wait(w1)
        assert(ok, res1)
        ngx.say(res1)
        ngx.say(res2)
    }
--- stream_response
w1: reused 0
w2: timeout
--- error_log
lua tcp socket queue connect operation for connection pool "legacy_posted_waiters"
--- no_error_log
[error]
--- timeout: 4



=== TEST 69: conn queuing: a pre-pool connection cannot exceed a busy pool
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local pool = "legacy_busy_pool"
        local legacy = assert(ngx.socket.connect("127.0.0.1", port,
                                                {pool = pool}))
        local opts = {pool = pool, pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        assert(legacy:setkeepalive())

        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local ok, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", ok or err)
        if ok then
            extra:close()
        end

        assert(holder:close())
        local sock = assert(ngx.socket.connect("127.0.0.1", port, opts))
        ngx.say("after close: reused ", sock:getreusedtimes())
        sock:close()
    }
--- stream_response
extra: timeout
after close: reused 0
--- error_log
lua tcp socket queue connect operation for connection pool "legacy_busy_pool"
--- no_error_log
[error]



=== TEST 70: conn queuing: a pre-pool connection can use spare capacity
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local pool = "legacy_spare_capacity"
        local legacy = assert(ngx.socket.connect("127.0.0.1", port,
                                                {pool = pool}))
        local opts = {pool = pool, pool_size = 2, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        assert(legacy:setkeepalive())

        local newcomer = assert(ngx.socket.connect("127.0.0.1", port, opts))
        ngx.say("newcomer: reused ", newcomer:getreusedtimes())

        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local ok, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", ok or err)
        if ok then
            extra:close()
        end

        newcomer:close()
        holder:close()
    }
--- stream_response
newcomer: reused 1
extra: timeout
--- error_log
lua tcp socket queue connect operation for connection pool "legacy_spare_capacity"
--- no_error_log
[error]



=== TEST 71: conn queuing: a posted reuse leaves spare capacity available
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local semaphore = require "ngx.semaphore"
        local ready = semaphore.new()
        local release = semaphore.new()
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "posted_reuse_capacity", pool_size = 2,
                      backlog = 3}
        local holder1 = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local holder2 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local waiter = ngx.thread.spawn(function()
            local sock = assert(ngx.socket.connect("127.0.0.1", port, opts))
            local reused = sock:getreusedtimes()
            ready:post()
            assert(release:wait(2))
            sock:close()
            return "waiter: reused " .. reused
        end)

        assert(holder1:setkeepalive())
        assert(holder2:close())

        -- The waiter owns holder1's connection. The slot closed by
        -- holder2 is available even before that posted reuse runs.
        local newcomer = ngx.socket.tcp()
        newcomer:settimeout(100)
        local ok, err = newcomer:connect("127.0.0.1", port, opts)
        local res = ok and "newcomer: reused " .. newcomer:getreusedtimes()
                       or "newcomer: " .. err
        assert(ready:wait(2))

        -- Both slots are now occupied: subtracting the reservation must
        -- not give another caller a third slot.
        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local connected, extra_err = extra:connect("127.0.0.1", port, opts)
        if connected then
            extra:close()
        end

        if ok then
            newcomer:close()
        end

        release:post()
        local waited, wres = ngx.thread.wait(waiter)
        assert(waited, wres)
        ngx.say(wres)
        ngx.say(res)
        ngx.say("extra: ", connected or extra_err)
    }
--- stream_response
waiter: reused 1
newcomer: reused 0
extra: timeout
--- error_log
lua tcp socket queue connect operation for connection pool "posted_reuse_capacity"
--- no_error_log
[error]
--- timeout: 4



=== TEST 72: conn queuing: a reserved connection does not consume backlog twice
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "reserved_backlog", pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter(name)
            return ngx.thread.spawn(function()
                local sock = ngx.socket.tcp()
                sock:settimeout(1000)
                local ok, err = sock:connect("127.0.0.1", port, opts)
                if not ok then
                    return name .. ": " .. err
                end

                local reused = sock:getreusedtimes()
                assert(sock:setkeepalive())
                return name .. ": reused " .. reused
            end)
        end

        local w1 = waiter("w1")
        assert(holder:setkeepalive())

        -- w1 already owns the connection. Only w2 uses the backlog slot;
        -- the next connect must still be rejected while it waits.
        local w2 = waiter("w2")
        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local ok, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", ok or err)
        if ok then
            extra:close()
        end

        local ok1, res1 = ngx.thread.wait(w1)
        local ok2, res2 = ngx.thread.wait(w2)
        assert(ok1, res1)
        assert(ok2, res2)
        ngx.say(res1)
        ngx.say(res2)
    }
--- stream_response
extra: too many waiting connect operations
w1: reused 1
w2: reused 2
--- error_log
lua tcp socket queue connect operation for connection pool "reserved_backlog"
--- no_error_log
[error]



=== TEST 73: conn queuing: cancelling the last posted waiter releases its reservation
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "cancel_last_reserved", pool_size = 1,
                      backlog = 2}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local waiter = ngx.thread.spawn(function()
            assert(ngx.socket.connect("127.0.0.1", port, opts))
            error("cancelled waiter resumed")
        end)

        assert(holder:setkeepalive())
        assert(ngx.thread.kill(waiter))
        local newcomer = assert(ngx.socket.connect("127.0.0.1", port, opts))
        ngx.say("newcomer: reused ", newcomer:getreusedtimes())

        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local ok, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", ok or err)
        if ok then
            extra:close()
        end

        newcomer:close()
    }
--- stream_response
newcomer: reused 1
extra: timeout
--- error_log
lua tcp socket queue connect operation for connection pool "cancel_last_reserved"
--- no_error_log
[error]



=== TEST 74: conn queuing: a timer exiting before its handoff runs releases it
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "aborted_handoff", pool_size = 1, backlog = 1}

        assert(ngx.timer.at(0, function()
            local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
            ngx.thread.spawn(function()
                assert(ngx.socket.connect("127.0.0.1", port, opts))
                error("aborted waiter resumed")
            end)

            -- the handoff is posted, then the timer ends before it runs
            assert(holder:setkeepalive())
            return ngx.exit(ngx.OK)
        end))

        ngx.sleep(0.05)

        local sock = assert(ngx.socket.connect("127.0.0.1", port, opts))
        ngx.say("reused: ", sock:getreusedtimes())

        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local ok, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", ok or err)
        if ok then
            extra:close()
        end

        sock:close()
    }
--- stream_response
reused: 1
extra: timeout
--- error_log
lua tcp socket abort queueing
--- no_error_log
[error]



=== TEST 75: conn queuing: cancelling an owner cannot release a recycled item
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "recycled_handoff", pool_size = 2, backlog = 2}
        local holder1 = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local holder2 = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter(name)
            return ngx.thread.spawn(function()
                local sock = ngx.socket.tcp()
                sock:settimeout(500)
                assert(sock:connect("127.0.0.1", port, opts))
                local reused = sock:getreusedtimes()
                assert(sock:setkeepalive())
                return name .. ": reused " .. reused
            end)
        end

        local w1 = waiter("w1")
        local w2 = waiter("w2")
        local spinner = ngx.thread.spawn(function()
            coroutine.yield()
            assert(holder1:setkeepalive(1))

            local t = ngx.now()
            repeat
                ngx.update_time()
            until ngx.now() - t >= 0.005
        end)

        ngx.sleep(0.002)

        -- w1's connection closed, returning its item to the free list.
        -- Reuse that item for w2 before cancelling w1: the cancellation
        -- must release only w1's empty slot, leaving w2's connection alone.
        assert(holder2:setkeepalive())
        local killed, err = ngx.thread.kill(w1)
        assert(killed, err)
        assert(ngx.thread.wait(spinner))

        local sock = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local reused = sock:getreusedtimes()
        local ok, res = ngx.thread.wait(w2)
        assert(ok, res)
        ngx.say("killed: ", killed)
        ngx.say(res)
        ngx.say("newcomer: reused ", reused)
        sock:close()
    }
--- stream_response
killed: 1
w2: reused 1
newcomer: reused 0
--- error_log
lua tcp socket keepalive max idle timeout
--- no_error_log
[error]



=== TEST 76: conn queuing: reconnect cannot overwrite a waiting socket
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "busy_queued", pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local sock = ngx.socket.tcp()
        sock:settimeout(1000)
        local waiter = ngx.thread.spawn(function()
            assert(sock:connect("127.0.0.1", port, opts))
            error("cancelled waiter resumed")
        end)

        local other = {pool = "busy_other", pool_size = 1, backlog = 1}
        local ok, err = sock:connect("127.0.0.1", port, other)
        ngx.say("second: ", ok or err)
        ngx.say("killed: ", assert(ngx.thread.kill(waiter)))
        holder:close()

        -- Cancellation clears the busy state before this socket is reused.
        assert(sock:connect("127.0.0.1", port, other))
        ngx.say("retry: reused ", sock:getreusedtimes())
        sock:close()
    }
--- stream_response
second: socket busy connecting
killed: 1
retry: reused 0
--- error_log
lua tcp socket abort queueing
--- no_error_log
[error]



=== TEST 77: conn queuing: rejected reconnect preserves a posted socket's pool
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "busy_posted", pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local sock = ngx.socket.tcp()
        local waiter = ngx.thread.spawn(function()
            assert(sock:connect("127.0.0.1", port, opts))
            assert(sock:setkeepalive())
        end)

        assert(holder:setkeepalive())
        local other = {pool = "posted_other", pool_size = 1, backlog = 1}
        local ok, err = sock:connect("127.0.0.1", port, other)
        ngx.say("second: ", ok or err)
        assert(ngx.thread.wait(waiter))

        local next_sock = assert(ngx.socket.connect("127.0.0.1", port, opts))
        ngx.say("original pool: reused ", next_sock:getreusedtimes())
        next_sock:close()
    }
--- stream_response
second: socket busy connecting
original pool: reused 2
--- error_log
lua tcp socket queue connect operation for connection pool "busy_posted"
--- no_error_log
[error]



=== TEST 78: conn queuing: a timed out socket can connect again
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "busy_timeout", pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local sock = ngx.socket.tcp()
        sock:settimeout(50)
        local waiter = ngx.thread.spawn(function()
            local ok, err = sock:connect("127.0.0.1", port, opts)
            return ok or err
        end)
        local ok, res = ngx.thread.wait(waiter)
        assert(ok, res)
        ngx.say("first: ", res)

        sock:settimeout(1000)
        local other = {pool = "timeout_retry", pool_size = 1, backlog = 1}
        assert(sock:connect("127.0.0.1", port, other))
        ngx.say("retry: reused ", sock:getreusedtimes())
        sock:close()
        holder:close()
    }
--- stream_response
first: timeout
retry: reused 0
--- error_log
lua tcp socket queue connect operation for connection pool "busy_timeout"
--- no_error_log
[error]



=== TEST 79: conn queuing: a socket cancelled after handoff can connect again
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "busy_cancelled", pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local sock = ngx.socket.tcp()
        local waiter = ngx.thread.spawn(function()
            assert(sock:connect("127.0.0.1", port, opts))
            error("cancelled waiter resumed")
        end)

        assert(holder:setkeepalive())
        ngx.say("killed: ", assert(ngx.thread.kill(waiter)))
        assert(sock:connect("127.0.0.1", port, opts))
        ngx.say("retry: reused ", sock:getreusedtimes())
        sock:close()
    }
--- stream_response
killed: 1
retry: reused 1
--- error_log
lua tcp socket abort queueing
--- no_error_log
[error]



=== TEST 80: conn queuing: killing a parent cancels its posted child coroutine
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "nested_cancel", pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local parent = ngx.thread.spawn(function()
            coroutine.wrap(function()
                local sock = ngx.socket.tcp()
                assert(sock:connect("127.0.0.1", port, opts))
                error("cancelled descendant resumed")
            end)()
        end)

        assert(holder:setkeepalive())
        assert(ngx.thread.kill(parent))
        parent = nil
        collectgarbage("collect")
        collectgarbage("collect")

        local sock = assert(ngx.socket.connect("127.0.0.1", port, opts))
        ngx.say("reused: ", sock:getreusedtimes())

        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local ok, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", ok or err)
        if ok then
            assert(extra:close())
        end

        assert(sock:close())
    }
--- stream_response
reused: 1
extra: timeout
--- error_log
lua tcp socket abort queueing
--- no_error_log
[error]



=== TEST 81: conn queuing: a waiter resumed in the preread phase takes the handed connection
--- stream_server_config
    lua_socket_log_errors off;

    preread_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "preread_handoff", pool_size = 1, backlog = 2}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local waiter = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            assert(sock:connect("127.0.0.1", port, opts))
            local reused = sock:getreusedtimes()
            assert(sock:setkeepalive())
            return reused
        end)

        -- the handoff resumes the waiter outside the content phase
        assert(holder:setkeepalive())
        local ok, reused = ngx.thread.wait(waiter)
        assert(ok, reused)
        ngx.ctx.reused = reused
    }

    content_by_lua_block {
        ngx.say("preread waiter: reused ", ngx.ctx.reused)
    }
--- stream_response
preread waiter: reused 1
--- error_log
lua tcp socket queue connect operation for connection pool "preread_handoff"
--- no_error_log
[error]



=== TEST 82: conn queuing: a stale connection returned to the pool passes its slot to a waiter
--- config
    location = /ka {
        return 200 "ok";
    }
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "stale_handoff", pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local waiter = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            local ok, err = sock:connect("127.0.0.1", port, opts)
            if not ok then
                return "waiter: " .. err
            end

            local reused = sock:getreusedtimes()
            assert(sock:setkeepalive())
            return "waiter: reused " .. reused
        end)

        local req = "GET /ka HTTP/1.1\r\nHost: localhost\r\n\r\n"
        assert(holder:send(req))
        local read_headers = holder:receiveuntil("\r\n\r\n")
        assert(read_headers())
        assert(holder:receive(2))

        -- An unread response makes the connection readable when it goes
        -- back to the pool: it is closed there, and its slot must go to
        -- the waiter exactly once.
        assert(holder:send(req))
        ngx.sleep(0.05)

        local ok, err = holder:setkeepalive()
        ngx.say("setkeepalive: ", ok or err)

        local ok, res = ngx.thread.wait(waiter)
        assert(ok, res)
        ngx.say(res)

        local sock = ngx.socket.tcp()
        sock:settimeout(1000)
        assert(sock:connect("127.0.0.1", port, opts))
        ngx.say("newcomer: reused ", sock:getreusedtimes())

        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local connected, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", connected or err)
        if connected then
            extra:close()
        end

        sock:close()
    }
--- stream_response
setkeepalive: connection in dubious state
waiter: reused 0
newcomer: reused 1
extra: timeout
--- error_log
lua tcp socket keepalive close handler: fd:
--- no_error_log
[error]



=== TEST 83: conn queuing: waiters refused by the backend pass their slots on
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "refused_backend", pool_size = 1, backlog = 2}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local function waiter(name)
            return ngx.thread.spawn(function()
                local sock = ngx.socket.tcp()
                sock:settimeout(1000)
                ngx.update_time()
                local start = ngx.now()

                -- nothing listens on port 1
                local ok, err = sock:connect("127.0.0.1", 1, opts)
                ngx.update_time()
                local slow = ngx.now() - start >= 0.5 and " (slow)" or ""
                if ok then
                    sock:close()
                    return name .. ": connected" .. slow
                end

                return name .. ": " .. err .. slow
            end)
        end

        local w1 = waiter("w1")
        local w2 = waiter("w2")

        -- Each refused waiter must hand the slot to the next one
        -- instead of leaving it to the connect timeout.
        assert(holder:close())

        for _, th in ipairs({w1, w2}) do
            local ok, res = ngx.thread.wait(th)
            assert(ok, res)
            ngx.say(res)
        end

        local sock = assert(ngx.socket.connect("127.0.0.1", port, opts))
        ngx.say("after: reused ", sock:getreusedtimes())

        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local connected, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", connected or err)
        if connected then
            extra:close()
        end

        sock:close()
    }
--- stream_response
w1: connection refused
w2: connection refused
after: reused 0
extra: timeout
--- error_log
lua tcp socket queue connect operation for connection pool "refused_backend"
--- no_error_log
[error]



=== TEST 84: conn queuing: a request ending without closing its socket resumes a waiter
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "unclosed_holder", pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        assert(ngx.timer.at(0, function()
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            local ok, err = sock:connect("127.0.0.1", port, opts)
            if not ok then
                ngx.log(ngx.WARN, "waiter: ", err)
                return
            end

            local reused = sock:getreusedtimes()
            local extra = ngx.socket.tcp()
            extra:settimeout(50)
            local connected, cerr = extra:connect("127.0.0.1", port, opts)
            if connected then
                extra:close()
            end

            sock:close()
            ngx.log(ngx.WARN, "waiter: reused ", reused, ", extra: ",
                    connected or cerr)
        end))

        -- let the timer queue behind the holder
        ngx.sleep(0.01)
        ngx.say(holder and "done")

        -- the holder is left open: the request cleanup closes it and
        -- must hand its slot to the waiting timer
    }
--- stream_response
done
--- error_log
waiter: reused 0, extra: timeout
--- no_error_log
[error]
--- wait: 0.5



=== TEST 85: conn queuing: a waiter cancelled by the end of its timer frees its backlog place
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "ended_waiter", pool_size = 1, backlog = 1}
        local holder = assert(ngx.socket.connect("127.0.0.1", port, opts))

        assert(ngx.timer.at(0, function()
            ngx.thread.spawn(function()
                assert(ngx.socket.connect("127.0.0.1", port, opts))
                error("cancelled waiter resumed")
            end)

            -- the timer ends while its light thread is still queued
            return ngx.exit(ngx.OK)
        end))

        ngx.sleep(0.05)

        -- the timer's waiter was cancelled while still queued, so the only
        -- backlog place must be free again
        local newcomer = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            local ok, err = sock:connect("127.0.0.1", port, opts)
            if not ok then
                return "newcomer: " .. err
            end

            local reused = sock:getreusedtimes()
            sock:close()
            return "newcomer: reused " .. reused
        end)

        assert(holder:setkeepalive())
        local ok, r = ngx.thread.wait(newcomer)
        assert(ok, r)
        ngx.say(r)
    }
--- stream_response
newcomer: reused 1
--- error_log
lua tcp socket abort queueing
--- no_error_log
[error]



=== TEST 86: conn queuing: a reconnect rejected as busy reading keeps the socket's pool
--- config
    location = /ka {
        return 200 "ok";
    }
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local sock = ngx.socket.tcp()
        assert(sock:connect("127.0.0.1", port, {pool = "reading_pool"}))
        assert(sock:send("GET /ka HTTP/1.1\r\nHost: localhost\r\n\r\n"))

        local reader = ngx.thread.spawn(function()
            local read_headers = sock:receiveuntil("\r\n\r\n")
            assert(read_headers())
            return assert(sock:receive(2))
        end)

        -- rejected while the reader waits: the pool key must not change
        local ok, err = sock:connect("127.0.0.1", port, {pool = "other_pool"})
        ngx.say("reconnect: ", ok or err)

        local ok, body = ngx.thread.wait(reader)
        assert(ok, body)
        assert(sock:setkeepalive())

        local again = assert(ngx.socket.connect("127.0.0.1", port,
                                                {pool = "reading_pool"}))
        ngx.say("reading_pool: reused ", again:getreusedtimes())
        again:close()
    }
--- stream_response
reconnect: socket busy reading
reading_pool: reused 1
--- error_log
lua tcp socket keepalive create connection pool for key "reading_pool"
--- no_error_log
[error]



=== TEST 87: conn queuing: a pre-pool connection replaces an idle connection in a full pool
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local pool = "legacy_replaces_idle"
        local legacy = assert(ngx.socket.connect("127.0.0.1", port,
                                                {pool = pool}))
        local opts = {pool = pool, pool_size = 2, backlog = 1}

        -- fill the pool: one active connection and one idle connection,
        -- reused once, while a free item is still left
        local idle = assert(ngx.socket.connect("127.0.0.1", port, opts))
        assert(idle:setkeepalive())
        idle = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local active = assert(ngx.socket.connect("127.0.0.1", port, opts))
        assert(idle:setkeepalive())

        -- the uncounted connection may only take the idle one's place
        assert(legacy:setkeepalive())

        local sock = assert(ngx.socket.connect("127.0.0.1", port, opts))
        ngx.say("reused: ", sock:getreusedtimes())

        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local connected, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", connected or err)
        if connected then
            extra:close()
        end

        sock:close()
        active:close()
    }
--- stream_response
reused: 1
extra: timeout
--- error_log
lua tcp socket queue connect operation for connection pool "legacy_replaces_idle"
--- no_error_log
[error]



=== TEST 88: conn queuing: a fast shutdown frees pools with queued connects and idle connections
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local ffi = require "ffi"
        pcall(ffi.cdef, [[
            int getpid(void);
            int kill(int pid, int sig);
        ]])

        -- collected by lua_close(), which runs after the pools are freed
        local marker = newproxy(true)
        getmetatable(marker).__gc = function()
            ngx.log(ngx.WARN, "Lua VM closed after the pool cleanup")
        end
        package.loaded.fast_shutdown_marker = marker

        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "fast_shutdown", pool_size = 1, backlog = 2}

        -- another pool keeps an idle connection until the shutdown
        local idle = assert(ngx.socket.connect("127.0.0.1", port,
                                               {pool = "fast_shutdown_idle",
                                                pool_size = 1, backlog = 1}))
        assert(idle:setkeepalive())

        assert(ngx.timer.at(0, function()
            local holder = assert(ngx.socket.connect("127.0.0.1", port,
                                                     opts))
            for _ = 1, 2 do
                ngx.thread.spawn(function()
                    local sock = ngx.socket.tcp()
                    sock:settimeout(10000)
                    sock:connect("127.0.0.1", port, opts)
                end)
            end

            ngx.sleep(10)
            holder:close()
        end))

        -- let the timer queue its connects
        ngx.sleep(0.05)
        ngx.say("ok")

        -- the process exits once the response is out, with both connects
        -- still queued (the http server driving the test runs in it too)
        assert(ngx.timer.at(0.05, function()
            ffi.C.kill(ffi.C.getpid(), 15)
        end))
    }
--- stream_response
ok
--- error_log
lua tcp socket keepalive: free connection pool
Lua VM closed after the pool cleanup
--- no_error_log
[alert]
--- wait: 0.3



=== TEST 89: conn queuing: a waiter resumed with an empty slot reuses a connection cached before it runs
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local opts = {pool = "empty_slot_reuse", pool_size = 2, backlog = 1}
        local a = assert(ngx.socket.connect("127.0.0.1", port, opts))
        local b = assert(ngx.socket.connect("127.0.0.1", port, opts))

        local w = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            sock:settimeout(1000)
            assert(sock:connect("127.0.0.1", port, opts))
            return sock
        end)

        -- a frees an empty slot for w; before w runs, b goes back to the
        -- pool with nobody waiting any more
        assert(a:close())
        assert(b:setkeepalive())

        local ok, sock = ngx.thread.wait(w)
        assert(ok, sock)
        ngx.say("w: reused ", sock:getreusedtimes())

        -- w gave its spare slot back: one more connection fits
        local c = ngx.socket.tcp()
        c:settimeout(100)
        local ok, err = c:connect("127.0.0.1", port, opts)
        ngx.say("c: ", ok and "reused " .. c:getreusedtimes() or err)

        local extra = ngx.socket.tcp()
        extra:settimeout(50)
        local connected, err = extra:connect("127.0.0.1", port, opts)
        ngx.say("extra: ", connected or err)
        if connected then
            extra:close()
        end

        if ok then
            c:close()
        end

        sock:close()
    }
--- stream_response
w: reused 1
c: reused 0
extra: timeout
--- error_log
lua tcp socket resumed connect operation reuses an idle connection, releasing its spare slot
--- no_error_log
[error]
