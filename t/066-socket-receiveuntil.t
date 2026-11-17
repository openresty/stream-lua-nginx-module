# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

no_long_string();
#no_diff();
#log_level 'warn';

run_tests();

__DATA__

=== TEST 1: memcached read lines
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_MEMCACHED_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "get __nil\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local readline = sock:receiveuntil("\r\n")
        local line, err, part = readline()
        if line then
            ngx.say("received: ", line)

        else
            ngx.say("failed to receive a line: ", err, " [", part, "]")
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }
--- stream_response
connected: 1
request sent: 11
received: END
close: 1 nil
--- no_error_log
[error]



=== TEST 2: http read lines
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local readline = sock:receiveuntil("\r\n")
        local line, err, part

        for i = 1, 7 do
            line, err, part = readline()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        content_by_lua_block { ngx.say("foo") }
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: HTTP/1.1 200 OK
read: Server: nginx
read: Content-Type: text/plain
read: Content-Length: 4
read: Connection: close
read: 
failed to read a line: closed [foo
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 3: http read all the headers in a single run
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local line, err, part

        for i = 1, 2 do
            line, err, part = read_headers()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        content_by_lua_block { ngx.say("foo") }
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: HTTP/1.1 200 OK\r
Server: nginx\r
Content-Type: text/plain\r
Content-Length: 4\r
Connection: close
failed to read a line: closed [foo
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 4: ambiguous boundary patterns (abcabd)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("abcabd")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        content_by_lua_block { ngx.say("abcabcabd") }
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: abc
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 5: ambiguous boundary patterns (aa)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("aa")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        content_by_lua_block { ngx.say("abcabcaad") }
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: abcabc
failed to read a line: closed [d
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 6: ambiguous boundary patterns (aaa)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("aaa")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo abaabcaaaef;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: abaabc
failed to read a line: closed [ef
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 7: ambiguous boundary patterns (aaaaad)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("aaaaad")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo baaaaaaaaeaaaaaaadf;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: baaaaaaaaeaa
failed to read a line: closed [f
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 8: ambiguous boundary patterns (aaaaad), small buffer, 2 bytes
--- stream_server_config
    lua_socket_buffer_size 2;

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("aaaaad")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo baaaaaaaaeaaaaaaadf;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: baaaaaaaaeaa
failed to read a line: closed [f
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 9: ambiguous boundary patterns (aaaaad), small buffer, 1 byte
--- stream_server_config
    lua_socket_buffer_size 1;

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("aaaaad")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo baaaaaaaaeaaaaaaadf;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: baaaaaaaaeaa
failed to read a line: closed [f
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 10: ambiguous boundary patterns (abcabdabcabe)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("abcabdabcabe")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo abcabdabcabdabcabe;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: abcabd
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 11: ambiguous boundary patterns (abcabdabcabe 2)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("abcabdabcabe")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo abcabdabcabcabdabcabe;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: abcabdabc
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 12: ambiguous boundary patterns (abcabdabcabe 3)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("abcabdabcabe")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo abcabcabdabcabe;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: abc
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 13: ambiguous boundary patterns (abcabdabcabe 4)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("abcabdabcabe")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo ababcabdabcabe;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: ab
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 14: ambiguous boundary patterns (--abc)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("--abc")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo -- ----abc;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: --
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 15: ambiguous boundary patterns (--abc)
--- stream_server_config
    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("--abc")

        for i = 1, 6 do
            line, err, part = reader(4)
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo "hello, world ----abc";
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: hell
read: o, w
read: orld
read:  --
failed to read a line: nil [nil]
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 16: ambiguous boundary patterns (--abc), small buffer
--- stream_server_config
    lua_socket_buffer_size 1;

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("--abc")

        for i = 1, 6 do
            line, err, part = reader(4)
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo "hello, world ----abc";
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: hell
read: o, w
read: orld
read:  --
failed to read a line: nil [nil]
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 17: ambiguous boundary patterns (--abc), small buffer, mixed by other reading calls
--- stream_server_config
    lua_socket_buffer_size 1;

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("--abc")

        for i = 1, 7 do
            line, err, part = reader(4)
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a chunk: ", err, " [", part, "]")
            end

            local data, err, part = sock:receive(1)
            if not data then
                ngx.say("failed to read a byte: ", err, " [", part, "]")
                break
            else
                ngx.say("read one byte: ", data)
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo "hello, world ----abc";
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: hell
read one byte: o
read: , wo
read one byte: r
read: ld -
read one byte: -
read: 
read one byte: 

failed to read a chunk: nil [nil]
failed to read a byte: closed []
close: 1 nil
}
--- no_error_log
[error]



=== TEST 18: ambiguous boundary patterns (abcabd), small buffer
--- stream_server_config
    lua_socket_buffer_size 3;

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("abcabd")

        for i = 1, 2 do
            line, err, part = reader()
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo abcabcabd;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: abc
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 19: long patterns
this exposed a memory leak in receiveuntil
--- stream_server_config
    content_by_lua_block {
        local sock, err = ngx.req.socket()
        if not sock then
            ngx.say("failed to get req socket: ", err)
            return
        end
        local reader, err = sock:receiveuntil("------------------------------------------- abcdefghijklmnopqrstuvwxyz")
        if not reader then
            ngx.say("failed to get reader: ", err)
            return
        end
        ngx.say("ok")
    }
--- stream_response
ok
--- no_error_log
[error]



=== TEST 20: close the socket after the iterator got a read error and was GC'ed (GH #2517)
--- stream_server_config
    content_by_lua_block {
        -- JIT traces may keep the iterator closure alive
        jit.off()
        jit.flush()

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        local weak = setmetatable({}, { __mode = "v" })

        local function read_until_error()
            local reader = sock:receiveuntil("--no-such-boundary")
            weak[1] = reader

            while true do
                local data, err = reader(1)
                if not data then
                    ngx.say("failed to read: ", err)
                    return
                end
            end
        end

        read_until_error()

        for _ = 1, 4 do
            collectgarbage("collect")
        end

        ngx.say("reader collected: ", weak[1] == nil)

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }
--- config
    server_tokens off;
    location = /foo {
        content_by_lua_block {
            ngx.print("hello world")
        }
    }
--- stream_response
failed to read: closed
reader collected: true
close: 1 nil
--- no_error_log
[error]



=== TEST 21: close socket after receiveuntil iterator is GC'ed following a successful read
--- stream_server_config
    content_by_lua_block {
        jit.off()
        jit.flush()

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local req = "GET /slow HTTP/1.0\r\nHost: localhost\r\n\r\n"
        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        local weak = setmetatable({}, { __mode = "v" })

        local function read_until_match()
            local reader = sock:receiveuntil("hello")
            weak[1] = reader
            local data, err = reader()
            ngx.say("matched: ", data ~= nil and err == nil)
        end

        read_until_match()
        for _ = 1, 4 do
            collectgarbage("collect")
        end
        ngx.say("reader collected: ", weak[1] == nil)

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }
--- config
    server_tokens off;
    location = /slow {
        lua_http10_buffering off;
        content_by_lua_block {
            ngx.print("hello")
            ngx.flush(true)
            ngx.sleep(0.2)
        }
    }
--- stream_response
matched: true
reader collected: true
close: 1 nil
--- no_error_log
[error]



=== TEST 22: retry the same iterator after a timeout with a partial delimiter
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local sock = ngx.socket.tcp()
        assert(sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT))
        assert(sock:send("GET /slow HTTP/1.0\r\nHost: localhost\r\n\r\n"))

        local headers = sock:receiveuntil("\r\n\r\n")
        assert(headers())

        local reader = sock:receiveuntil("abcabd")
        sock:settimeout(100)
        local data, err, partial = reader()
        ngx.say("first: ", data, " ", err, " [", partial, "]")

        collectgarbage("collect")

        sock:settimeout(1000)
        data, err = reader()
        ngx.say("retry: [", data, "] ", err)

        data, err = reader()
        ngx.say("next: [", data, "] ", err)

        local ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }
--- config
    location = /slow {
        lua_http10_buffering off;
        content_by_lua_block {
            ngx.print("abc")
            ngx.flush(true)
            ngx.sleep(0.3)
            ngx.print("abdtailabcabd")
        }
    }
--- stream_response
first: nil timeout []
retry: [] nil
next: [tail] nil
close: 1 nil
--- no_error_log
[error]



=== TEST 23: close socket after receiveuntil iterator is GC'ed following a timeout
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        jit.off()
        jit.flush()

        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local bytes, err = sock:send("GET /slow HTTP/1.0\r\n\r\n")
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        local headers = sock:receiveuntil("\r\n\r\n")
        local data, err = headers()
        if not data then
            ngx.say("failed to read headers: ", err)
            return
        end

        sock:settimeout(100)
        local weak = setmetatable({}, { __mode = "v" })

        local function read_until_timeout()
            local reader = sock:receiveuntil("abcabd")
            weak[1] = reader
            local data, err, partial = reader()
            ngx.say("read: ", data, " ", err, " [", partial, "]")
        end

        read_until_timeout()
        for _ = 1, 4 do
            collectgarbage("collect")
        end

        ngx.say("reader collected: ", weak[1] == nil)

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }
--- config
    location = /slow {
        lua_http10_buffering off;
        content_by_lua_block {
            ngx.print("abc")
            ngx.flush(true)
            ngx.sleep(0.3)
        }
    }
--- stream_response
read: nil timeout []
reader collected: true
close: 1 nil
--- no_error_log
[error]



=== TEST 24: add pending bytes
--- stream_server_config
    lua_socket_buffer_size 1;

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("--abc")

        for i = 1, 4 do
            local line, err, part = reader(2)
            if line then
                ngx.say("read: ", line)

            else
                ngx.say("failed to read a line: ", err, " [", part, "]")
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo -- -----abc;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: --
read: -
failed to read a line: nil [nil]
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 25: ambiguous boundary patterns (--abc), mixed by other reading calls consume boundary
--- stream_server_config

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("--abc")

        for i = 1, 5 do
            local line, err, part = reader(2)
            if not line then
                ngx.say("failed to read a line: ", err, " [", part, "]")
                break

            else
                ngx.say("read: ", line)
            end

            local data, err, part = sock:receive(1)
            if not data then
                ngx.say("failed to read a byte: ", err, " [", part, "]")
                break

            else
                ngx.say("read one byte: ", data)
            end
        end

        local line, err, part = reader(2)
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo -- ----abc----abc-;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: --
read one byte: -
read: -a
read one byte: b
read: c-
read one byte: -
read:\x20
read one byte: -
failed to read a line: nil [nil]
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 26: ambiguous boundary patterns (--abc), mixed by other reading calls (including receiveuntil) consume boundary
--- stream_server_config

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader1 = sock:receiveuntil("--abc")
        local reader2 = sock:receiveuntil("-ab")

        local line, err, part = reader1(2)
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        local data, err, part = sock:receive(1)
        if not data then
            ngx.say("failed to read a byte: ", err, " [", part, "]")

        else
            ngx.say("read one byte: ", data)
        end

        local line, err, part = reader1(1)
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        local line, err, part = reader2(2)
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        local line, err, part = reader1()
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        local line, err, part = reader1()
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo -- ------abd----abc;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: --
read one byte: -
read: -
read: -
read: d--
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 27: ambiguous boundary patterns (--abc), mixed by other reading calls consume boundary, small buffer
--- stream_server_config
    lua_socket_buffer_size 3;

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader = sock:receiveuntil("--abc")

        for i = 1, 5 do
            local line, err, part = reader(2)
            if not line then
                ngx.say("failed to read a line: ", err, " [", part, "]")
                break

            else
                ngx.say("read: ", line)
            end

            local data, err, part = sock:receive(1)
            if not data then
                ngx.say("failed to read a byte: ", err, " [", part, "]")
                break

            else
                ngx.say("read one byte: ", data)
            end
        end

        local line, err, part = reader(2)
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo -- ----abc----abc-;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: --
read one byte: -
read: -a
read one byte: b
read: c-
read one byte: -
read:\x20
read one byte: -
failed to read a line: nil [nil]
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 28: ambiguous boundary patterns (--abc), mixed by other reading calls (including receiveuntil) consume boundary, small buffer
--- stream_server_config
    lua_socket_buffer_size 3;

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        local reader1 = sock:receiveuntil("--abc")
        local reader2 = sock:receiveuntil("-ab")

        local line, err, part = reader1(2)
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        local data, err, part = sock:receive(1)
        if not data then
            ngx.say("failed to read a byte: ", err, " [", part, "]")

        else
            ngx.say("read one byte: ", data)
        end

        local line, err, part = reader1(1)
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        local line, err, part = reader2(2)
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        local line, err, part = reader1()
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        local line, err, part = reader1()
        if not line then
            ngx.say("failed to read a line: ", err, " [", part, "]")

        else
            ngx.say("read: ", line)
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo -- ------abd----abc;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: --
read one byte: -
read: -
read: -
read: d--
failed to read a line: closed [
]
close: 1 nil
}
--- no_error_log
[error]



=== TEST 29: ambiguous boundary patterns (ab1ab2), ends half way
--- stream_server_config

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        if true then
            local reader = sock:receiveuntil("ab1ab2")

            local line, err, part = reader(2)
            if not line then
                ngx.say("failed to read a line: ", err, " [", part, "]")

            else
                ngx.say("read: ", line)
            end
        end

        collectgarbage("collect")

        local data, err, part = sock:receive(3)
        if not data then
            ngx.say("failed to read three bytes: ", err, " [", part, "]")

        else
            ngx.say("read three bytes: ", data)
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo -- ab1ab1;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: ab1
read three bytes: ab1
close: 1 nil
}
--- no_error_log
[error]



=== TEST 30: ambiguous boundary patterns (ab1ab2), ends half way, small buffer
--- stream_server_config
    lua_socket_buffer_size 3;

    content_by_lua_block {
        -- collectgarbage("collect")

        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT

        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end
        ngx.say("request sent: ", bytes)

        local read_headers = sock:receiveuntil("\r\n\r\n")
        local headers, err, part = read_headers()
        if not headers then
            ngx.say("failed to read headers: ", err, " [", part, "]")
        end

        if true then
            local reader = sock:receiveuntil("ab1ab2")

            local line, err, part = reader(2)
            if not line then
                ngx.say("failed to read a line: ", err, " [", part, "]")

            else
                ngx.say("read: ", line)
            end
        end

        collectgarbage("collect")

        local data, err, part = sock:receive(3)
        if not data then
            ngx.say("failed to read three bytes: ", err, " [", part, "]")

        else
            ngx.say("read three bytes: ", data)
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

--- config
    server_tokens off;
    location = /foo {
        echo -- ab1ab1;
        more_clear_headers Date;
    }
--- stream_response eval
qq{connected: 1
request sent: 57
read: ab1
read three bytes: ab1
close: 1 nil
}
--- no_error_log
[error]



=== TEST 31: switch readers after a timeout and iterator collection
--- stream_server_config
    lua_socket_log_errors off;
    lua_socket_buffer_size 1;

    content_by_lua_block {
        jit.off()
        jit.flush()

        for _, mode in ipairs({ "receive", "receiveany", "receiveuntil" }) do
            local sock = ngx.socket.tcp()
            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            local bytes, err = sock:send("GET /slow HTTP/1.0\r\n\r\n")
            if not bytes then
                ngx.say("failed to send: ", err)
                return
            end

            local headers = sock:receiveuntil("\r\n\r\n")
            local data, err = headers()
            if not data then
                ngx.say("failed to read headers: ", err)
                return
            end

            sock:settimeout(100)
            local weak = setmetatable({}, { __mode = "v" })

            local function read_until_timeout()
                local reader = sock:receiveuntil("abcabd")
                weak[1] = reader
                local data, err, partial = reader()
                ngx.say(mode, ": ", data, " ", err, " [", partial, "]")
            end

            read_until_timeout()
            for _ = 1, 4 do
                collectgarbage("collect")
            end

            ngx.say("reader collected: ", weak[1] == nil)

            if mode == "receiveuntil" then
                local reader = sock:receiveuntil("c", { inclusive = true })
                data, err = reader()

            else
                data, err = sock[mode](sock, 3)
            end

            ngx.say("restored: [", data, "] ", err)

            ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end
    }
--- config
    location = /slow {
        lua_http10_buffering off;
        content_by_lua_block {
            ngx.print("abc")
            ngx.flush(true)
            ngx.sleep(0.3)
        }
    }
--- stream_response
receive: nil timeout []
reader collected: true
restored: [abc] nil
close: 1 nil
receiveany: nil timeout []
reader collected: true
restored: [abc] nil
close: 1 nil
receiveuntil: nil timeout []
reader collected: true
restored: [abc] nil
close: 1 nil
--- no_error_log
[error]



=== TEST 32: request socket retains a pending delimiter after timeout and GC
--- stream_server_config
    lua_socket_log_errors off;
    lua_socket_buffer_size 1;

    content_by_lua_block {
        local sock, err = ngx.req.socket()
        if not sock then
            ngx.say("failed to get request socket: ", err)
            return
        end

        sock:settimeout(100)

        local reader = sock:receiveuntil("abcabd")
        local data, err, partial = reader()
        ngx.say("read: ", data, " ", err, " [", partial, "]")

        reader = nil
        collectgarbage("collect")

        data, err = sock:receive(3)
        ngx.say("restored: [", data, "] ", err)
    }
--- stream_request chop
abc
--- stream_response
read: nil timeout []
restored: [abc] nil
--- no_error_log
[error]
