# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Dgram;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 1);

our $HtmlDir = html_dir;

#$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

no_long_string();
#no_diff();
#log_level 'warn';
no_shuffle();

run_tests();

__DATA__

=== TEST 1: sanity
--- ONLY
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket()
        if not sock then
            ngx.log(ngx.ERR, "failed to get the request socket: ", err)
            return ngx.exit(ngx.ERROR)
        end

        local data, err = sock:receive()
        if not data then
            ngx.log(ngx.ERR, "failed to receive: ", err)
            return ngx.exit(ngx.ERROR)
        end

        -- print("data: ", data)

        local ok, err = sock:send("received: " .. data)
        if not ok then
            ngx.log(ngx.ERR, "failed to send: ", err)
            return ngx.exit(ngx.ERROR)
        end
    }
--- dgram_request chomp
hello world! my
--- dgram_response chomp
received: hello world! my
--- no_error_log
[error]



=== TEST 2: attempt to use the req socket across request boundary
--- dgram_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua';"
--- dgram_server_config
    content_by_lua_block {
        local test = require "test"
        test.go()
        ngx.say("done")
    }
--- user_files
>>> test.lua
module("test", package.seeall)

local sock, err

function go()
    if not sock then
        sock, err = ngx.req.udp_socket()
        if sock then
            ngx.say("got the request socket")
        else
            ngx.say("failed to get the request socket: ", err)
        end
    else
        for i = 1, 3 do
            local data, err, part = sock:receive(5)
            if data then
                ngx.say("received: ", data)
            else
                ngx.say("failed to receive: ", err, " [", part, "]")
            end
        end
    end
end
--- dgram_response_like
(?:got the request socket
|failed to receive: closed [d]
)?done
--- no_error_log
[alert]



=== TEST 3: pipelined POST requests
--- dgram_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua';"
--- dgram_server_config
    content_by_lua_block {
        local test = require "test"
        test.go()
        ngx.say("done")
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go()
   local sock, err = ngx.req.udp_socket()
   if sock then
      ngx.say("got the request socket")
   else
      ngx.say("failed to get the request socket: ", err)
      return
   end

   for i = 1, 5 do
       local data, err, part = sock:receive(4)
       if data then
          ngx.say("received: ", data)
       else
          ngx.say("failed to receive: ", err, " [", part, "]")
          return
       end
   end
end
--- dgram_request chomp
hello, worldhiya, wo
--- dgram_response
got the request socket
received: hell
received: o, w
received: orld
received: hiya
received: , wo
done
--- no_error_log
[error]



=== TEST 4: pipelined requests, big buffer, small steps
--- dgram_server_config
    lua_socket_buffer_size 5;
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket()
        if sock then
            ngx.say("got the request socket")
        else
            ngx.say("failed to get the request socket: ", err)
        end

        for i = 1, 11 do
            local data, err, part = sock:receive(2)
            if data then
                ngx.say("received: ", data)
            else
                ngx.say("failed to receive: ", err, " [", part, "]")
            end
        end
    }
--- stap2
M(http-lua-req-socket-consume-preread) {
    println("preread: ", user_string_n($arg2, $arg3))
}

--- dgram_request chomp
hello world
hiya globe
--- dgram_response
got the request socket
received: he
received: ll
received: o
received: wo
received: rl
received: d

received: hi
received: ya
received:  g
received: lo
received: be
--- no_error_log
[error]



=== TEST 5: failing reread after reading timeout happens
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket()

        if not sock then
           ngx.say("failed to get socket: ", err)
           return nil
        end

        sock:settimeout(100);

        local data, err, partial = sock:receive(4096)
        if err then
           ngx.say("err: ", err, ", partial: ", partial)
        end

        local data, err, partial = sock:receive(4096)
        if err then
           ngx.say("err: ", err, ", partial: ", partial)
           return
        end
    }

--- dgram_request chomp
hello
--- dgram_response
err: timeout, partial: hello
err: timeout, partial:

--- error_log
stream lua udp socket read timed out



=== TEST 6: req socket GC'd
--- dgram_server_config
    content_by_lua_block {
        do
            local sock, err = ngx.req.udp_socket()
            if sock then
                ngx.say("got the request socket")
            else
                ngx.say("failed to get the request socket: ", err)
            end
        end
        collectgarbage()
        ngx.log(ngx.WARN, "GC cycle done")

        ngx.say("done")
    }
--- dgram_response
got the request socket
done
--- no_error_log
[error]
--- grep_error_log eval: qr/stream lua finalize socket|GC cycle done/
--- grep_error_log_out
stream lua finalize socket
GC cycle done
