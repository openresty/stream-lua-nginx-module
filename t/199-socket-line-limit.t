# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * blocks() * 3;

no_long_string();
no_shuffle();
run_tests();

__DATA__

=== TEST 1: downstream default line receive rejects data above the limit
--- stream_config
    lua_socket_max_line_size 4;
--- stream_server_config
    lua_socket_buffer_size 2;
    lua_socket_log_errors off;

    content_by_lua_block {
        local sock = assert(ngx.req.socket())
        local line, err, part = sock:receive()
        ngx.say("line: ", line)
        ngx.say("error: ", err)
        ngx.say("partial: ", part)

        line, err = sock:receive()
        ngx.say("again: ", line, " ", err)
    }
--- stream_request: abcde
--- stream_response
line: nil
error: line too long
partial: abcd
again: nil closed
--- no_error_log
[error]



=== TEST 2: carriage returns count toward the upstream line limit
--- stream_config
    server {
        listen 127.0.0.1:$TEST_NGINX_RAND_PORT_1;
        content_by_lua_block {
            ngx.print("\r\r\r\r\r")
        }
    }
--- stream_server_config
    lua_socket_buffer_size 2;
    lua_socket_max_line_size 4;

    content_by_lua_block {
        local sock = assert(ngx.socket.connect("127.0.0.1",
                                               $TEST_NGINX_RAND_PORT_1))
        local line, err, part = sock:receive("*l")
        ngx.say("line: ", line)
        ngx.say("error: ", err)
        ngx.say("partial bytes: ", #part)
    }
--- stream_response
line: nil
error: line too long
partial bytes: 0
--- no_error_log
[error]



=== TEST 3: an upstream line exactly at the limit succeeds
--- stream_config
    server {
        listen 127.0.0.1:$TEST_NGINX_RAND_PORT_2;
        content_by_lua_block {
            ngx.say("abcd")
        }
    }
--- stream_server_config
    lua_socket_buffer_size 2;
    lua_socket_max_line_size 4;

    content_by_lua_block {
        local sock = assert(ngx.socket.connect("127.0.0.1",
                                               $TEST_NGINX_RAND_PORT_2))
        local line, err = sock:receive("*l")
        ngx.say("line: ", line)
        ngx.say("error: ", err)
    }
--- stream_response
line: abcd
error: nil
--- no_error_log
[error]



=== TEST 4: partial progress does not refresh the line deadline
--- stream_config
    lua_socket_line_read_timeout 100ms;
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local sock = assert(ngx.socket.connect("127.0.0.1",
                                               $TEST_NGINX_SERVER_PORT))
        assert(sock:send("GET /slow HTTP/1.0\r\nHost: localhost\r\n\r\n"))

        local read_headers = sock:receiveuntil("\r\n\r\n")
        assert(read_headers())

        sock:settimeout(2000)
        local line, err, part = sock:receive()
        ngx.say("line: ", line)
        ngx.say("error: ", err)
        ngx.say("partial: ", part)
    }
--- config
    location = /slow {
        content_by_lua_block {
            ngx.header.content_length = 4
            for _, byte in ipairs({ "a", "b", "c", "d" }) do
                ngx.print(byte)
                ngx.flush(true)
                ngx.sleep(0.06)
            end
        }
    }
--- stream_response
line: nil
error: timeout
partial: ab
--- no_error_log
[error]



=== TEST 5: the default accepts a line longer than 64k
--- stream_config
    server {
        listen 127.0.0.1:$TEST_NGINX_RAND_PORT_1;
        content_by_lua_block {
            ngx.say(string.rep("x", 65537))
        }
    }
--- stream_server_config
    content_by_lua_block {
        local sock = assert(ngx.socket.connect("127.0.0.1",
                                               $TEST_NGINX_RAND_PORT_1))
        local line = assert(sock:receive())
        ngx.say(#line)
    }
--- stream_response
65537
--- no_error_log
[error]



=== TEST 6: a server can disable inherited limits
--- stream_config
    lua_socket_max_line_size 4;
    lua_socket_line_read_timeout 50ms;
    server {
        listen 127.0.0.1:$TEST_NGINX_RAND_PORT_2;
        content_by_lua_block {
            ngx.sleep(0.2)
            ngx.say("hello")
        }
    }
--- stream_server_config
    lua_socket_max_line_size 0;
    lua_socket_line_read_timeout 0;

    content_by_lua_block {
        local sock = assert(ngx.socket.connect("127.0.0.1",
                                               $TEST_NGINX_RAND_PORT_2))
        ngx.say(assert(sock:receive("*l")))
    }
--- stream_response
hello
--- no_error_log
[error]



=== TEST 7: default line reads can outlast the socket idle timeout
--- stream_config
    server {
        listen 127.0.0.1:$TEST_NGINX_RAND_PORT_2;
        content_by_lua_block {
            for i = 1, 3 do
                ngx.print("a")
                ngx.flush(true)
                ngx.sleep(0.35)
            end
            ngx.say("b")
        }
    }
--- stream_server_config
    content_by_lua_block {
        local sock = assert(ngx.socket.connect("127.0.0.1",
                                               $TEST_NGINX_RAND_PORT_2))
        sock:settimeout(800)
        ngx.say(assert(sock:receive()))
    }
--- stream_response
aaab
--- no_error_log
[error]
