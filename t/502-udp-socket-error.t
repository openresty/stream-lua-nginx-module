# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

if (defined $ENV{TEST_NGINX_SKIP_COSOCKET_LOG_TEST}) {
    plan(skip_all => "Remove TEST_NGINX_SKIP_COSOCKET_LOG_TEST to enable this test");
} else {
    plan tests => repeat_each() * (3 * blocks());
}

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

#log_level 'warn';

no_long_string();
#no_diff();
#no_shuffle();
check_accum_error_log();
run_tests();

__DATA__

=== TEST 1: access a TCP interface
--- stream_server_config

    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local socket = ngx.socket
        -- local socket = require "socket"

        local udp = socket.udp()

        local port = $TEST_NGINX_SERVER_PORT
        udp:settimeout(1000) -- 1 sec

        local ok, err = udp:setpeername("localhost", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected")

        local req = "\0\1\0\0\0\1\0\0flush_all\r\n"
        local ok, err = udp:send(req)
        if not ok then
            ngx.say("failed to send: ", err)
            return
        end

        local data, err = udp:receive()
        if not data then
            ngx.say("failed to receive data: ", err)
            return
        end
        ngx.print("received ", #data, " bytes: ", data)
    }

--- config
    server_tokens off;
--- stream_response
connected
failed to receive data: connection refused
--- error_log eval
qr/recv\(\) failed \(\d+: Connection refused\), upstream: localhost:\d+\(127.0.0.1\)/



=== TEST 2: recv timeout
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;

    content_by_lua_block {
        local port = $TEST_NGINX_MEMCACHED_PORT

        local sock = ngx.socket.udp()
        sock:settimeout(100) -- 100 ms

        local ok, err = sock:setpeername("localhost", port)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local line, err = sock:receive()
        if line then
            ngx.say("received: ", line)

        else
            ngx.say("failed to receive: ", err)
        end

        -- ok, err = sock:close()
        -- ngx.say("close: ", ok, " ", err)
    }

--- stream_response
connected: 1
failed to receive: timeout
--- error_log
lua udp socket read timed out, upstream: localhost:11211(127.0.0.1), 



=== TEST 3: read timeout and re-receive
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local udp = ngx.socket.udp()
        udp:settimeout(30)
        local ok, err = udp:setpeername("localhost", 19232)
        if not ok then
            ngx.say("failed to setpeername: ", err)
            return
        end
        local ok, err = udp:send("blah")
        if not ok then
            ngx.say("failed to send: ", err)
            return
        end
        for i = 1, 2 do
            local data, err = udp:receive()
            if err == "timeout" then
                -- continue
            else
                if not data then
                    ngx.say("failed to receive: ", err)
                    return
                end
                ngx.say("received: ", data)
                return
            end
        end

        ngx.say("timed out")
    }

--- udp_listen: 19232
--- udp_reply: hello world
--- udp_reply_delay: 45ms
--- stream_response
received: hello world
--- error_log
lua udp socket read timed out, upstream: localhost:19232(127.0.0.1)
