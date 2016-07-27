# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Dgram;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

#plan tests => repeat_each() * 43;

our $HtmlDir = html_dir;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();
run_tests();

__DATA__

=== TEST 1: sanity
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket(true)
        if not sock then
            ngx.log(ngx.ERR, "failed to get the request socket: ", err)
            return ngx.exit(ngx.ERROR)
        end

        local data, err = sock:receive()
        if not data then
            ngx.log(ngx.ERR, "failed to receive: ", err)
            return ngx.exit(ngx.ERROR)
        end

        local ok, err = sock:send("received: " .. data)
        if not ok then
            ngx.log(ngx.ERR, "failed to send: ", err)
            return ngx.exit(ngx.ERROR)
        end
    }

--- dgram_request
hello
--- dgram_response
received: hello
--- no_error_log
[error]



=== TEST 2: multiple raw req sockets
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket(true)
        if not sock then
            ngx.log(ngx.ERR, "failed to get raw request socket: ", err)
            return ngx.exit(ngx.ERROR)
        end
        assert(sock:send(""))

        local sock2, err = ngx.req.udp_socket(true)
        if not sock2 then
            ngx.log(ngx.ERR, "failed to get raw request socket: ", err)
            return ngx.exit(ngx.ERROR)
        end
    }

--- stap2
F(ngx_dgram_header_filter) {
    println("header filter")
}
F(ngx_dgram_lua_req_socket) {
    println("lua req socket")
}
--- dgram_response
--- error_log
failed to get raw request socket: duplicate call



=== TEST 3: sock:send after ngx.req.udp_socket(true)
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket(true)
        if not sock then
            ngx.log(ngx.ERR, "failed to get raw request socket: ", err)
            return ngx.exit(ngx.ERROR)
        end

        local ok, err = sock:send("ok")
        if not ok then
            ngx.log(ngx.ERR, "failed to send: ", err)
            return ngx.exit(ngx.ERROR)
        end
    }

--- dgram_response chomp
ok
--- no_error_log
[error]



=== TEST 4: receive timeout
--- SKIP
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket(true)
        if not sock then
            ngx.log(ngx.ERR, "failed to get raw request socket: ", err)
            return ngx.exit(ngx.ERROR)
        end

        local data, err = sock:receive() -- trigger_dgram_req

        sock:settimeout(100)
        data, err = sock:receive()
        if err then
          sock:send("err: ", err)
        end
    }

--- dgram_response chomp
err: timeout
--- error_log
stream lua udp socket read timed out



=== TEST 5: on_abort called during ngx.sleep()
--- dgram_server_config
    lua_check_client_abort on;

    content_by_lua_block {
        local ok, err = ngx.on_abort(function (premature) ngx.log(ngx.WARN, "mysock handler aborted") end)
        if not ok then
            ngx.log(ngx.ERR, "failed to set on_abort handler: ", err)
            return
        end

        local sock, err = ngx.req.udp_socket(true)
        if not sock then
            ngx.log(ngx.ERR, "failed to get raw request socket: ", err)
            return ngx.exit(ngx.ERROR)
        end

        local data, err = sock:receive()
        if not data then
            ngx.log(ngx.ERR, "server: failed to receive: ", err)
            return ngx.exit(ngx.ERROR)
        end

        print("msg received: ", data)

        local bytes, err = sock:send("1: received: " .. data .. "\n")
        if not bytes then
            ngx.log(ngx.ERR, "server: failed to send: ", err)
            return ngx.exit(ngx.ERROR)
        end

        ngx.sleep(1)
    }

--- dgram_request
hello
--- dgram_response
receive stream response error: timeout
--- abort
--- timeout: 0.2
--- warn_log
mysock handler aborted
--- no_error_log
[error]
--- wait: 1.1



=== TEST 6: on_abort called during sock:receive()
--- dgram_server_config
    lua_check_client_abort on;

    content_by_lua_block {
        local ok, err = ngx.on_abort(function (premature) ngx.log(ngx.WARN, "mysock handler aborted") end)
        if not ok then
            ngx.log(ngx.ERR, "failed to set on_abort handler: ", err)
            return
        end


        local sock, err = ngx.req.udp_socket(true)
        if not sock then
            ngx.log(ngx.ERR, "failed to get raw request socket: ", err)
            return ngx.exit(ngx.ERROR)
        end

        local data, err = sock:receive()
        if not data then
            ngx.log(ngx.ERR, "server: failed to receive: ", err)
            return ngx.exit(ngx.ERROR)
        end

        print("msg received: ", data)

        local bytes, err = sock:send("1: received: " .. data .. "\n")
        if not bytes then
            ngx.log(ngx.ERR, "server: failed to send: ", err)
            return ngx.exit(ngx.ERROR)
        end

        local data, err = sock:receive()
        if not data then
            ngx.log(ngx.WARN, "failed to receive a line: ", err)
            return
        end
    }

--- dgram_response
receive stream response error: timeout
--- timeout: 0.2
--- abort
--- warn_log
mysock handler aborted
--- no_error_log
[error]
--- wait: 0.1



=== TEST 7: request body not read yet
--- dgram_server_config
    content_by_lua_block {
      local sock, err = ngx.req.udp_socket(true)
      if not sock then
          ngx.log(ngx.ERR, "failed to get raw request socket: ", err)
          return ngx.exit(ngx.ERROR)
      end

      local data, err = sock:receive()
      if not data then
          ngx.log(ngx.ERR, "server: failed to receive: ", err)
          return ngx.exit(ngx.ERROR)
      end

      local ok, err = sock:send("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n" .. data)
      if not ok then
          ngx.log(ngx.ERR, "failed to send: ", err)
          return ngx.exit(ngx.ERROR)
      end
    }

--- dgram_request chomp
hello
--- dgram_response eval
"HTTP/1.1 200 OK\r
Content-Length: 5\r
\r
hello"

--- no_error_log
[error]
