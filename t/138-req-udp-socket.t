# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Dgram;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

our $HtmlDir = html_dir;

#$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

no_long_string();
#no_diff();
#log_level 'warn';
no_shuffle();

run_tests();

__DATA__

=== TEST 1: sanity
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

        local ok, err = sock:send("received: " .. data)
        if not ok then
            ngx.log(ngx.ERR, "failed to send: ", err)
            return ngx.exit(ngx.ERROR)
        end
    }

--- dgram_request
hello world! my
--- dgram_response
received: hello world! my
--- no_error_log
[error]


=== TEST 2: ngx.say not supported
--- dgram_server_config
    content_by_lua_block {
      local sock, err = ngx.req.udp_socket()
      sock:send("")
      ngx.say("something")
    }

--- dgram_response
--- error_log
not supported in udp requests



=== TEST 3: ngx.print not supported
--- dgram_server_config
    content_by_lua_block {
      local sock, err = ngx.req.udp_socket()
      sock:send("")
      ngx.print("something")
    }

--- dgram_response
--- error_log
not supported in udp requests



=== TEST 4: ngx.eof after ngx.req.udp_socket(true)
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket(true)
        if not sock then
            ngx.log(ngx.ERR, "failed to get raw request socket: ", err)
            return ngx.exit(ngx.ERROR)
        end
        assert(sock:send(""))
        ngx.eof()
}

--- config
server_tokens off;

--- dgram_response
--- error_log
not supported in udp requests



=== TEST 5: ngx.flush after ngx.udp_req.socket(true)
--- dgram_server_config
  content_by_lua_block {
      local sock, err = ngx.req.udp_socket(true)
      if not sock then
          ngx.log(ngx.ERR, "failed to get raw request socket: ", err)
          return ngx.exit(ngx.ERROR)
      end
      assert(sock:send(""))
      ngx.flush()
}

--- dgram_response
--- error_log
not supported in udp requests



=== TEST 6: receive (bad arg number)
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket()
        sock:send("")
        sock:receive(5,4)
    }

--- dgram_response
--- error_log
expecting 1 or 2 arguments (including the object), but got 3



=== TEST 7: failing reread after reading timeout happens
--- SKIP
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket()
        if not sock then
            ngx.log(ngx.ERR, "failed to get the request socket: ", err)
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



=== TEST 8: req socket GC'd
--- dgram_server_config
    content_by_lua_block {
        do
            local sock, err = ngx.req.udp_socket()
            if not sock then
                ngx.log(ngx.ERR, "failed to get the request socket: ", err)
                return ngx.exit(ngx.ERROR)
            end

            assert(sock:send("done"))
        end
        collectgarbage()
        ngx.log(ngx.WARN, "GC cycle done")
    }

--- dgram_response chomp
done
--- no_error_log
[error]
--- grep_error_log_out
stream lua finalize socket
GC cycle done
