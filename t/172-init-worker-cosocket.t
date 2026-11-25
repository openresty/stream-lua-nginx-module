# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

master_on();
repeat_each(1);

plan tests => repeat_each() * (blocks() * 3 + 3);

no_long_string();

# UDP echo server for the UDP cosocket test: memcached 1.6+ dropped the
# text-over-UDP protocol, so we echo datagrams ourselves
my $udp_echo_pid = fork();
if (!$udp_echo_pid) {
    require IO::Socket::INET;
    my $srv = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => 19849, Proto => 'udp')
        or die "udp echo bind: $!";
    while (my $peer = $srv->recv(my $buf, 4096)) {
        $srv->send($buf, 0, $peer);
    }
    exit 0;
}
END { kill 'KILL', $udp_echo_pid if $udp_echo_pid; }

our $HtmlDir = html_dir;

run_tests();

__DATA__



=== TEST 1: TCP cosocket connect/send/receive in init_worker_by_lua
--- stream_config eval
qq{
    lua_init_worker_timeout 10s;
    init_worker_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $ENV{TEST_NGINX_MEMCACHED_PORT})
        if not ok then
            iw_result = "connect failed: " .. (err or "unknown")
            return
        end

        local bytes, err = sock:send("flush_all\\r\\n")
        if not bytes then
            iw_result = "send failed: " .. (err or "unknown")
            return
        end

        local line, err = sock:receive()
        if not line then
            iw_result = "receive failed: " .. (err or "unknown")
            return
        end

        sock:close()
        iw_result = "received: " .. line
    }
}
--- stream_server_config
    content_by_lua_block {
        ngx.say(iw_result or "no result")
    }
--- stream_response
received: OK
--- timeout: 15
--- no_error_log
[error]



=== TEST 2: ngx.sleep in init_worker_by_lua
--- stream_config
    lua_init_worker_timeout 5s;
    init_worker_by_lua_block {
        local t0 = ngx.now()
        ngx.sleep(0.1)
        local t1 = ngx.now()
        ngx.sleep(0)
        local t2 = ngx.now()

        iw_done = true
        iw_slept = (t1 - t0) >= 0.09
        iw_zero_ok = (t2 - t1) < 1
    }
--- stream_server_config
    content_by_lua_block {
        ngx.say(iw_done    and "done"     or "not done")
        ngx.say(iw_slept   and "slept OK" or "sleep too short")
        ngx.say(iw_zero_ok and "zero OK"  or "zero hung")
    }
--- stream_response
done
slept OK
zero OK
--- no_error_log
[error]



=== TEST 3: semaphore wait in init_worker, posted by a spawned uthread
--- stream_config eval
qq{
    lua_init_worker_timeout 5s;
    init_worker_by_lua_block {
        local sema = require("ngx.semaphore").new(0)

        ngx.log(ngx.DEBUG, "iw: before spawn")
        local child, serr = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            local ok, err = sock:connect("127.0.0.1",
                                         $ENV{TEST_NGINX_MEMCACHED_PORT})
            if not ok then
                ngx.log(ngx.ERR, "child connect failed: ", err)
                return
            end
            sock:send("flush_all\\r\\n")
            sock:receive()
            sock:close()
            ngx.log(ngx.DEBUG, "iw: child posting")
            sema:post(1)
        end)
        iw_spawn_ok = child and true or false

        ngx.log(ngx.DEBUG, "iw: before wait")

        local wok, werr = sema:wait(3)

        ngx.log(ngx.DEBUG, "iw: after wait")
        iw_wait_ok = wok and true or false
        iw_wait_err = werr or "none"

        local jok = ngx.thread.wait(child)
        iw_join_ok = jok and true or false
    }
}
--- stream_server_config
    content_by_lua_block {
        ngx.say(iw_spawn_ok and "spawn OK" or "spawn failed")
        ngx.say(iw_wait_ok  and "wait OK"  or "wait failed: "
                .. (iw_wait_err or ""))
        ngx.say(iw_join_ok and "join OK" or "join failed")
    }
--- stream_response
spawn OK
wait OK
join OK
--- log_level: debug
--- grep_error_log eval: qr/iw: [^,\n]*/
--- grep_error_log_out
iw: before spawn
iw: before wait
iw: child posting
iw: after wait
--- no_error_log
[error]



=== TEST 4: non-yielding init_worker code behaves unchanged
--- stream_config
    init_worker_by_lua_block {
        foo = ngx.md5("hello world")
    }
--- stream_server_config
    content_by_lua_block {
        ngx.say("foo = ", foo)
    }
--- stream_response
foo = 5eb63bbbe01eeed093cb22bb8f5acdc3
--- no_error_log
[error]



=== TEST 5: timer.at registered in init_worker fires only after init finishes
--- stream_config
    lua_shared_dict iw_state 1m;
    init_worker_by_lua_block {
        local shdict = ngx.shared.iw_state
        shdict:set("chunk_done", 0)
        shdict:set("fires", 0)

        local ok, err = ngx.timer.at(0, function(premature)
            if premature then
                return
            end
            shdict:set("fires", (shdict:get("fires") or 0) + 1)
            if shdict:get("chunk_done") ~= 1 then
                shdict:set("bad_early", 1)
            end
        end)
        shdict:set("timer_ok", ok and 1 or 0)

        ngx.sleep(0.2)

        shdict:set("chunk_done", 1)
    }
--- stream_server_config
    content_by_lua_block {
        local shdict = ngx.shared.iw_state
        for i = 1, 100 do
            if (shdict:get("fires") or 0) >= 1 then
                break
            end
            ngx.sleep(0.02)
        end
        ngx.say("timer_ok: " .. (shdict:get("timer_ok") == 1 and "OK" or "FAIL"))
        ngx.say("fired: " .. ((shdict:get("fires") or 0) >= 1 and "OK" or "FAIL"))
        ngx.say("no early fire: " .. (shdict:get("bad_early") and "FAIL" or "OK"))
    }
--- stream_response
timer_ok: OK
fired: OK
no early fire: OK
--- timeout: 10
--- no_error_log
[error]



=== TEST 6: timer.every registered in init_worker fires only after init and renews
--- stream_config
    lua_shared_dict iw_state 1m;
    init_worker_by_lua_block {
        local shdict = ngx.shared.iw_state
        shdict:set("chunk_done", 0)
        shdict:set("fires", 0)

        local tok, err = ngx.timer.every(0.05, function(premature)
            if premature then
                return
            end
            shdict:set("fires", shdict:get("fires") + 1)
            if shdict:get("chunk_done") ~= 1 then
                shdict:set("bad_early", 1)
            end
        end)
        shdict:set("timer_ok", tok and 1 or 0)

        ngx.sleep(0.2)

        shdict:set("chunk_done", 1)
    }
--- stream_server_config
    content_by_lua_block {
        local shdict = ngx.shared.iw_state
        for i = 1, 100 do
            if (shdict:get("fires") or 0) >= 3 then
                break
            end
            ngx.sleep(0.05)
        end
        ngx.say("timer_ok: " .. (shdict:get("timer_ok") == 1 and "OK" or "FAIL"))
        ngx.say("renewal: " .. ((shdict:get("fires") or 0) >= 3 and "OK" or "FAIL"))
        ngx.say("no early fire: " .. (shdict:get("bad_early") and "FAIL" or "OK"))
    }
--- stream_response
timer_ok: OK
renewal: OK
no early fire: OK
--- timeout: 10
--- no_error_log
[error]



=== TEST 7: ngx.thread.spawn + wait, child does a cosocket roundtrip
--- stream_config eval
qq{
    lua_init_worker_timeout 5s;
    init_worker_by_lua_block {
        local child, err = ngx.thread.spawn(function()
            local sock = ngx.socket.tcp()
            local ok, err = sock:connect("127.0.0.1",
                                         $ENV{TEST_NGINX_MEMCACHED_PORT})
            if not ok then
                return "connect failed: " .. (err or "?")
            end
            sock:send("flush_all\\r\\n")
            local line = sock:receive()
            sock:close()
            return "child: " .. line
        end)
        iw_spawn_ok = child and true or false
        local ok, res = ngx.thread.wait(child)
        iw_wait_ok = ok and true or false
        iw_child_ret = res or "none"
    }
}
--- stream_server_config
    content_by_lua_block {
        ngx.say(iw_spawn_ok and "spawn OK" or "spawn failed")
        ngx.say(iw_wait_ok  and "wait OK"  or "wait failed")
        ngx.say(iw_child_ret)
    }
--- stream_response
spawn OK
wait OK
child: OK
--- timeout: 15
--- no_error_log
[error]



=== TEST 8: UDP cosocket roundtrip in init_worker
--- stream_config
    lua_init_worker_timeout 5s;
    init_worker_by_lua_block {
        local sock = ngx.socket.udp()
        local ok, err = sock:setpeername("127.0.0.1", 19849)
        if not ok then
            iw_udp_result = "setpeername failed: " .. (err or "?")
            return
        end
        sock:settimeout(2000)
        local bytes, err = sock:send("ping")
        if not bytes then
            iw_udp_result = "send failed: " .. (err or "?")
            return
        end
        local data, err = sock:receive()
        if not data then
            iw_udp_result = "receive failed: " .. (err or "?")
            return
        end
        sock:close()
        iw_udp_result = "received: " .. data
    }
--- stream_server_config
    content_by_lua_block {
        ngx.say(iw_udp_result or "no result")
    }
--- stream_response
received: ping
--- timeout: 10
--- no_error_log
[error]



=== TEST 9: cosocket connect via resolver in init_worker
--- stream_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    lua_init_worker_timeout 10s;
    init_worker_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeout(5000)
        local ok, err = sock:connect("openresty.org", 80)
        if not ok then
            iw_resolver_result = "connect failed: " .. (err or "?")
            return
        end
        sock:close()
        iw_resolver_result = "connected"
    }
--- stream_server_config
    content_by_lua_block {
        ngx.say(iw_resolver_result or "no result")
    }
--- stream_response
connected
--- timeout: 15
--- no_error_log
[error]



=== TEST 10: SSL cosocket handshake in init_worker
--- stream_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    lua_init_worker_timeout 10s;
    init_worker_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeout(5000)
        local ok, err = sock:connect("openresty.org", 443)
        if not ok then
            iw_ssl_result = "connect failed: " .. (err or "?")
            return
        end

        local session, err = sock:sslhandshake(nil, "openresty.org", false)
        if not session then
            iw_ssl_result = "ssl handshake failed: " .. (err or "?")
            return
        end

        sock:close()
        iw_ssl_result = "handshake OK"
    }
--- stream_server_config
    content_by_lua_block {
        ngx.say(iw_ssl_result or "no result")
    }
--- stream_response
handshake OK
--- timeout: 15
--- no_error_log
[error]



=== TEST 11: stalled remote read times out via lua_init_worker_timeout, worker starts
--- stream_config eval
qq{
    lua_init_worker_timeout 500ms;
    init_worker_by_lua_block {
        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $ENV{TEST_NGINX_MEMCACHED_PORT})
        if not ok then
            return
        end
        sock:send("get")   -- incomplete command: memcached waits forever
        sock:receive()     -- hangs here; the 500ms budget aborts mid-read
    }
}
--- stream_server_config
    content_by_lua_block {
        ngx.say("still serving")
    }
--- stream_response
still serving
--- timeout: 10
--- error_log
init_worker_by_lua* timed out



=== TEST 12: compile error keeps the legacy log prefix, worker still starts
--- stream_config
    init_worker_by_lua_block {
        local x =
        -- nothing after the "=": syntax error at load time
    }
--- stream_server_config
    content_by_lua_block {
        ngx.say("still serving")
    }
--- stream_response
still serving
--- error_log
init_worker_by_lua error:
--- no_error_log
lua run thread returned:



=== TEST 13: runtime error with default abort_on_error off, worker still starts
--- stream_config
    init_worker_by_lua_block {
        error("boom")   -- runtime error before any yield
    }
--- stream_server_config
    content_by_lua_block {
        ngx.say("still serving")
    }
--- stream_response
still serving
--- error_log
lua entry thread aborted:
--- no_error_log
init_worker_by_lua error:
