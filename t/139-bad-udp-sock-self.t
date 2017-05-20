# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Dgram;
repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

our $HtmlDir = html_dir;

#$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

no_long_string();
#no_diff();
#log_level 'warn';

run_tests();

__DATA__

=== TEST 1: receive
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket()
        sock:send("")
        sock.receive("l")
    }

--- dgram_response
--- error_log
bad argument #1 to 'receive' (table expected, got string)



=== TEST 2: send (bad arg number)
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket()
        sock:send("")
        sock.send("hello")
    }

--- dgram_response
--- error_log
expecting 2 arguments (including the object), but got 1



=== TEST 3: send (bad self)
--- dgram_server_config
    content_by_lua_block {
        local sock, err = ngx.req.udp_socket()
        sock:send("")
        sock.send("hello", 32)
    }

--- dgram_response
--- error_log
bad argument #1 to 'send' (table expected, got string)
