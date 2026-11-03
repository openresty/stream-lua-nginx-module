# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

# single-process mode (no master_on): an init_process failure exits
# the whole nginx with code 2, which --- must_die asserts

repeat_each(1);

$Test::Nginx::Util::DaemonEnabled = 'off';

plan tests => repeat_each() * (blocks() * 2);

no_long_string();
run_tests();

__DATA__

=== TEST 1: abort_on_error on + runtime error before yield exits with code 2
--- stream_config
   lua_init_worker_abort_on_error on;
   init_worker_by_lua_block {
       error("boom")   -- runtime error before any yield
   }
--- stream_server_config
    content_by_lua_block {
        ngx.say("never reached")
    }
--- must_die: 2
--- error_log
lua entry thread aborted:



=== TEST 2: abort_on_error on + init_worker timeout exits with code 2
--- stream_config eval
qq{
   lua_init_worker_abort_on_error on;
   lua_init_worker_timeout 500ms;
   init_worker_by_lua_block {
       local sock = ngx.socket.tcp()
       local ok, err = sock:connect("127.0.0.1", $ENV{TEST_NGINX_MEMCACHED_PORT})
       if not ok then
           return
       end
       sock:send("get")   -- incomplete command: memcached waits forever
       sock:receive()     -- hangs; the 500ms budget aborts mid-read
   }
}
--- stream_server_config
    content_by_lua_block {
        ngx.say("never reached")
    }
--- must_die: 2
--- error_log
init_worker_by_lua* timed out
