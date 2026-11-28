# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * blocks() * 3;

no_long_string();
no_shuffle();
run_tests();

__DATA__

=== TEST 1: downstream default line receive rejects data above the limit
--- stream_server_config
    lua_socket_buffer_size 2;
    lua_socket_max_line_size 4;
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
--- tcp_listen: $TEST_NGINX_RAND_PORT_1
--- tcp_reply eval: "\r\r\r\r\r"
--- no_error_log
[error]



=== TEST 3: an upstream line exactly at the limit succeeds
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
--- tcp_listen: $TEST_NGINX_RAND_PORT_2
--- tcp_reply eval: "abcd\n"
--- no_error_log
[error]



=== TEST 4: partial progress does not refresh the line deadline
--- stream_server_config
    lua_socket_log_errors off;

    content_by_lua_block {
        local sock = assert(ngx.socket.connect("127.0.0.1",
                                               $TEST_NGINX_SERVER_PORT))
        assert(sock:send("GET /slow HTTP/1.0\r\nHost: localhost\r\n\r\n"))

        local read_headers = sock:receiveuntil("\r\n\r\n")
        assert(read_headers())

        sock:settimeout(100)
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
