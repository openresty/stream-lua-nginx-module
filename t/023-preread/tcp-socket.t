# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
repeat_each(2);

plan tests => repeat_each() * 24;

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

#log_level 'warn';

no_long_string();
#no_diff();
run_tests();

__DATA__

=== TEST 1: sanity
--- stream_config
server {
    listen 127.0.0.1:9988;

    return testing\npreread\n;
}

--- stream_server_config
    preread_by_lua_block {
        local sock = ngx.socket.tcp()
        local port = 9988
        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

    local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            -- req = "OK"

            local bytes, err = sock:send(req)
            if not bytes then
                ngx.say("failed to send request: ", err)
                return
            end

            ngx.say("request sent: ", bytes)

        while true do
            local line, err, part = sock:receive()
            if line then
                ngx.say("received: ", line)

            else
                ngx.say("failed to receive a line: ", err, " [", part, "]")
                break
            end
        end

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

    content_by_lua return;
--- stream_response
connected: 1
request sent: 57
received: testing
received: preread
failed to receive a line: connection reset by peer []
close: 1 nil
--- error_log
recv() failed (104: Connection reset by peer



=== TEST 3: no resolver defined
--- stream_server_config
    preread_by_lua_block {
        local sock = ngx.socket.tcp()
        local port = ngx.var.port
        local ok, err = sock:connect("agentzh.org", 1234)
        if not ok then
            ngx.say("failed to connect: ", err)
        end

        ngx.say("connected: ", ok)

        local req = "GET /foo HTTP/1.0\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n"
        -- req = "OK"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)
    }

    content_by_lua return;
--- stream_response
failed to connect: no resolver defined to resolve "agentzh.org"
connected: nil
failed to send request: closed
--- error_log
attempt to send data on a closed socket:



=== TEST 4: with resolver
--- timeout: 10
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    preread_by_lua_block {
        local sock = ngx.socket.tcp()
        local port = 80
        local ok, err = sock:connect("agentzh.org", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local req = "GET / HTTP/1.0\r\nHost: agentzh.org\r\nConnection: close\r\n\r\n"
        -- req = "OK"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)

        local line, err = sock:receive()
        if line then
            ngx.say("first line received: ", line)

        else
            ngx.say("failed to receive the first line: ", err)
        end

        line, err = sock:receive()
        if line then
            ngx.say("second line received: ", line)

        else
            ngx.say("failed to receive the second line: ", err)
        end
    }

    content_by_lua return;
--- stream_response
connected: 1
request sent: 56
first line received: HTTP/1.1 200 OK
second line received: Server: openresty
--- no_error_log
[error]



=== TEST 5: connection refused (tcp)
--- stream_server_config
    preread_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", 16787)
        ngx.say("connect: ", ok, " ", err)

        local bytes
        bytes, err = sock:send("hello")
        ngx.say("send: ", bytes, " ", err)

        local line
        line, err = sock:receive()
        ngx.say("receive: ", line, " ", err)

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

    content_by_lua return;
--- stream_response
connect: nil connection refused
send: nil closed
receive: nil closed
close: nil closed
--- error_log eval
qr/connect\(\) failed \(\d+: Connection refused\)/



=== TEST 6: connection timeout (tcp)
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    lua_socket_connect_timeout 100ms;
    lua_socket_send_timeout 100ms;
    lua_socket_read_timeout 100ms;
    resolver_timeout 3s;
    preread_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("agentzh.org", 12345)
        ngx.say("connect: ", ok, " ", err)

        local bytes
        bytes, err = sock:send("hello")
        ngx.say("send: ", bytes, " ", err)

        local line
        line, err = sock:receive()
        ngx.say("receive: ", line, " ", err)

        ok, err = sock:close()
        ngx.say("close: ", ok, " ", err)
    }

    content_by_lua return;
--- stream_response
connect: nil timeout
send: nil closed
receive: nil closed
close: nil closed
--- error_log
lua tcp socket connect timed out
--- timeout: 10



=== TEST 7: not closed manually
--- stream_server_config
    preread_by_lua_block {
        local sock = ngx.socket.tcp()
        local port = $TEST_NGINX_SERVER_PORT
        local ok, err = sock:connect("127.0.0.1", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)
    }

    content_by_lua return;
--- stream_response
connected: 1
--- no_error_log
[error]



=== TEST 8: resolver error (host not found)
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    preread_by_lua_block {
        local sock = ngx.socket.tcp()
        local port = 80
        local ok, err = sock:connect("blah-blah-not-found.agentzh.org", 1234)
        print("connected: ", ok, " ", err, " ", not ok)
        if not ok then
            ngx.say("failed to connect: ", err)
        end

        ngx.say("connected: ", ok)

        local req = "GET / HTTP/1.0\\r\\nHost: agentzh.org\\r\\nConnection: close\\r\\n\\r\\n"
        -- req = "OK"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)
    }

    content_by_lua return;
--- stream_response_like
^failed to connect: blah-blah-not-found\.agentzh\.org could not be resolved(?: \(3: Host not found\))?
connected: nil
failed to send request: closed$
--- error_log
attempt to send data on a closed socket
--- timeout: 10



=== TEST 9: resolver error (timeout)
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 1ms;
    preread_by_lua_block {
        local sock = ngx.socket.tcp()
        local port = 80
        local ok, err = sock:connect("blah-blah-not-found.agentzh.org", port)
        print("connected: ", ok, " ", err, " ", not ok)
        if not ok then
            ngx.say("failed to connect: ", err)
        end

        ngx.say("connected: ", ok)

        local req = "GET / HTTP/1.0\\r\\nHost: agentzh.org\\r\\nConnection: close\\r\\n\\r\\n"
        -- req = "OK"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        ngx.say("request sent: ", bytes)
    }

    content_by_lua return;
--- stream_response_like
^failed to connect: blah-blah-not-found\.agentzh\.org could not be resolved(?: \(\d+: (?:Operation timed out|Host not found)\))?
connected: nil
failed to send request: closed$
--- error_log
attempt to send data on a closed socket



