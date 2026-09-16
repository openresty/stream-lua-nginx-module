# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

master_on();
repeat_each(1);

plan tests => repeat_each() * (blocks() * 3 + 2);

no_long_string();

run_tests();

__DATA__



=== TEST 1: accept deferred, pump stays idle (1 worker, level-triggered)
--- stream_config
    init_worker_by_lua_block {
        ngx.log(ngx.DEBUG, "iw: pump begin")
        ngx.sleep(1)
        ngx.log(ngx.DEBUG, "iw: pump done")
        iw_done = true
    }
--- stream_server_config
    content_by_lua_block {
        ngx.say(iw_done and "response ok" or "init_worker unfinished")
    }
--- stream_response
response ok
--- timeout: 15
--- log_level: debug
--- grep_error_log eval: qr/iw: pump [a-z]+/
--- grep_error_log_out
iw: pump begin
iw: pump done
--- no_error_log
[error]
exited on signal



=== TEST 2: cosocket in init_worker, then server accepts normally
--- stream_config eval
qq{
    lua_init_worker_timeout 10s;
    init_worker_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $ENV{TEST_NGINX_MEMCACHED_PORT})
        if not ok then
            iw_result = "connect failed: " .. (err or "?")
            return
        end
        sock:send("flush_all\\r\\n")
        local line = sock:receive()
        sock:close()
        iw_result = "cosocket: " .. line
    }
}
--- stream_server_config
    content_by_lua_block {
        ngx.say(iw_result or "no result")
        ngx.say("accept ok")
    }
--- stream_response
cosocket: OK
accept ok
--- timeout: 15
--- no_error_log
[error]
