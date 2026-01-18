# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

no_long_string();
run_tests();

__DATA__

=== TEST 1: UDP reqsock:peek returns prefix without consuming
--- stream_server_config
    preread_by_lua_block {
        local sock, err = ngx.req.socket()
        if not sock then
            ngx.say("no sock: ", err)
            return
        end

        local p, perr = sock.peek and sock:peek(8)
        ngx.say("peek:", p, ", err:", perr)

        local data, rerr = sock:receive()
        ngx.say("recv:", data, ", err:", rerr)
    }
    content_by_lua return;
--- stream_request chop
hello world
--- stream_response
peek:hello wo, err:nil
recv:hello world, err:nil
--- no_error_log
[error]



=== TEST 2: two consecutive peeks return same bytes
--- stream_server_config
    preread_by_lua_block {
        local sock = ngx.req.socket()
        local p1 = sock:peek(8)
        local p2 = sock:peek(8)
        ngx.say(p1 .. "|" .. p2)
    }
    content_by_lua return;
--- stream_request chop
abcdefghijk
--- stream_response
abcdefgh|abcdefgh
--- no_error_log
[error]



=== TEST 3: peek after receive() raises error
--- stream_server_config
    preread_by_lua_block {
        local sock = ngx.req.socket()
        local d = sock:receive(3)
        local ok, err = pcall(function() return sock:peek(1) end)
        ngx.say("ok=", ok, ", err=", err)
    }
    content_by_lua return;
--- stream_request chop
xyz
--- stream_response_like
^ok=false, err=attempt to peek on a consumed socket
--- no_error_log
[error]



=== TEST 4: timeout behavior (peek waits then times out)
--- SKIP: requires partial sends in harness
--- stream_server_config
    preread_by_lua_block {
        local sock = ngx.req.socket()
        local ok, err = pcall(function() return sock:peek(8) end)
        ngx.say("ok:", ok, ", err:", err)
    }
    content_by_lua return;
--- stream_request chop
hi
--- stream_response_like
^ok:false, err:.*timeout



=== TEST 5: buffer full behavior (peek errors when exceeded)
--- SKIP: requires controlled preread_buffer_size in harness
--- stream_config
    preread_buffer_size 8;
--- stream_server_config
    preread_by_lua_block {
        local sock = ngx.req.socket()
        local ok, err = pcall(function() return sock:peek(16) end)
        ngx.say("ok:", ok, ", err:", err)
    }
    content_by_lua return;
--- stream_request chop
abcdefghijklmnop
--- stream_response_like
^ok:false, err:.*buffer.*

