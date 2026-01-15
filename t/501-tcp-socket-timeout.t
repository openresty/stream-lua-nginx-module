# vim:set ft= ts=4 sw=4 et fdm=marker:

BEGIN {
    if (!defined $ENV{LD_PRELOAD}) {
        $ENV{LD_PRELOAD} = '';
    }

    if ($ENV{LD_PRELOAD} !~ /\bmockeagain\.so\b/) {
        $ENV{LD_PRELOAD} = "mockeagain.so $ENV{LD_PRELOAD}";
    }

    if ($ENV{MOCKEAGAIN} eq 'r') {
        $ENV{MOCKEAGAIN} = 'rw';

    } else {
        $ENV{MOCKEAGAIN} = 'w';
    }

    $ENV{TEST_NGINX_EVENT_TYPE} = 'poll';
    $ENV{MOCKEAGAIN_WRITE_TIMEOUT_PATTERN} = 'get helloworld';
}

use Test::Nginx::Socket::Lua::Stream;
use t::StapThread;

our $GCScript = $t::StapThread::GCScript;
our $StapScript = $t::StapThread::StapScript;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4 + 8);

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

log_level("debug");
no_long_string();
#no_diff();
run_tests();

__DATA__

=== TEST 1: lua_socket_connect_timeout only
--- stream_server_config
    lua_socket_connect_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("example.invalid", 12345)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)
    }
--- stream_response
failed to connect: example.invalid could not be resolved (3: Host not found)
--- error_log
lua tcp socket connect timeout: 100
--- timeout: 10



=== TEST 2: lua_socket_read_timeout only
--- stream_server_config
    lua_socket_read_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("localhost", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local line
        line, err = sock:receive()
        if line then
            ngx.say("received: ", line)
        else
            ngx.say("failed to receive: ", err)
        end
    }
--- stream_response
connected: 1
failed to receive: timeout
--- error_log
lua tcp socket read timeout: 100
lua tcp socket connect timeout: 60000
lua tcp socket read timed out
stream lua tcp socket read timed out, upstream: localhost:11211(127.0.0.1)



=== TEST 3: lua_socket_send_timeout only
--- stream_server_config
    lua_socket_send_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("localhost", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            ngx.say("sent: ", bytes)
        else
            ngx.say("failed to send: ", err)
        end
    }
--- stream_response
connected: 1
failed to send: timeout
--- error_log
lua tcp socket send timeout: 100
lua tcp socket connect timeout: 60000
stream lua tcp socket write timed out, upstream: localhost:11211(127.0.0.1)



=== TEST 4: re-connect after timed out
--- stream_server_config
    lua_socket_connect_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    resolver_timeout 3s;
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("127.0.0.2", 12345)
        if not ok then
            ngx.say("1: failed to connect: ", err)

            local ok, err = sock:connect("localhost", $TEST_NGINX_SERVER_PORT)
            if not ok then
                ngx.say("2: failed to connect: ", err)
                return
            end

            ngx.say("2: connected: ", ok)
            return
        end

        ngx.say("1: connected: ", ok)
    }
--- stream_response
1: failed to connect: timeout
2: connected: 1
--- error_log
lua tcp socket connect timeout: 100
stream lua tcp socket connect timed out, upstream: 127.0.0.2:12345(127.0.0.2)
--- timeout: 10



=== TEST 5: re-send on the same object after a send timeout happens
--- stream_server_config
    #lua_socket_send_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("localhost", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        sock:settimeout(100)

        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            ngx.say("sent: ", bytes)
        else
            ngx.say("failed to send: ", err)
            bytes, err = sock:send("blah")
            if not bytes then
                ngx.say("failed to send again: ", err)
            end
        end
    }
--- stream_response
connected: 1
failed to send: timeout
failed to send again: closed
--- error_log
lua tcp socket send timeout: 100
lua tcp socket connect timeout: 60000
lua tcp socket write timed out
stream lua tcp socket write timed out, upstream: localhost:11211(127.0.0.1)



=== TEST 6: read timeout on receive(N)
--- stream_server_config
    lua_socket_read_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("localhost", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        sock:settimeout(10)

        local line
        line, err = sock:receive(3)
        if line then
            ngx.say("received: ", line)
        else
            ngx.say("failed to receive: ", err)
        end
    }
--- stream_response
connected: 1
failed to receive: timeout
--- error_log
lua tcp socket read timeout: 10
lua tcp socket connect timeout: 60000
stream lua tcp socket read timed out, upstream: localhost:11211(127.0.0.1)



=== TEST 7: keepalive lua_socket_read_timeout
--- stream_server_config
    lua_socket_read_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("localhost", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)
        ngx.say("reusetime: ", sock:getreusedtimes())

        sock:setkeepalive()
        ok, err = sock:connect("localhost", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)
        ngx.say("reusetime: ", sock:getreusedtimes())

        local line
        line, err = sock:receive()
        if line then
            ngx.say("received: ", line)
        else
            ngx.say("failed to receive: ", err)
        end
    }
--- stream_response
connected: 1
reusetime: 0
connected: 1
reusetime: 1
failed to receive: timeout
--- error_log
lua tcp socket read timeout: 100
lua tcp socket connect timeout: 60000
lua tcp socket read timed out
stream lua tcp socket read timed out, upstream: localhost:11211(127.0.0.1)



=== TEST 8: keepalive lua_socket_send_timeout only
--- stream_server_config
    lua_socket_send_timeout 100ms;
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("localhost", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)
        ngx.say("reusetime: ", sock:getreusedtimes())

        sock:setkeepalive()
         ok, err = sock:connect("localhost", $TEST_NGINX_MEMCACHED_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)
        ngx.say("reusetime: ", sock:getreusedtimes())

        local bytes
        bytes, err = sock:send("get helloworld!")
        if bytes then
            ngx.say("sent: ", bytes)
        else
            ngx.say("failed to send: ", err)
        end
    }
--- stream_response
connected: 1
reusetime: 0
connected: 1
reusetime: 1
failed to send: timeout
--- error_log
lua tcp socket send timeout: 100
lua tcp socket connect timeout: 60000
stream lua tcp socket write timed out, upstream: localhost:11211(127.0.0.1)
