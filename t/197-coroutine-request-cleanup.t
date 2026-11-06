# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);
workers(1);
log_level('debug');
no_long_string();

plan tests => repeat_each() * blocks() * 5;

$ENV{TEST_NGINX_HTML_DIR} = html_dir();

our $Helpers = <<'_EOC_';
>>> sleep.lua
local co = coroutine.create(function()
    assert(ngx.shared.coroutine_cleanup:set("pending", true))
    ngx.sleep(10)
    error("aborted coroutine resumed")
end)
local ok, err = coroutine.resume(co)
assert(ok, err)

>>> abort.lua
local state = ngx.shared.coroutine_cleanup
state:delete("pending")
state:delete("finished")

local sock = ngx.socket.tcp()
sock:settimeout(2000)
assert(sock:connect("unix:" .. ngx.config.prefix() .. "html/victim.sock"))

local deadline = ngx.now() + 2
while not state:get("pending") do
    assert(ngx.now() < deadline, "ordinary coroutine did not sleep")
    ngx.sleep(0.001)
end

-- With one worker, the child has installed its timer before this session
-- can observe pending and close the real stream connection.
assert(sock:close())
while not state:get("finished") do
    assert(ngx.now() < deadline, "aborted session was not finalized")
    ngx.sleep(0.001)
end

-- Touch the timer tree again after the victim's pool was freed. ASan also
-- detects a stale node here without the fix.
ngx.sleep(0.001)
ngx.say("client abort cleanup: OK")

>>> exit.lua
local semaphore = require "ngx.semaphore"
local ready = semaphore.new()
ngx.thread.spawn(function()
    assert(ready:wait(2))
    ngx.say("request exit cleanup: OK")
    ngx.exit(200)
end)

local function sleep(depth)
    if depth == 0 then
        -- Posting wakes the exit thread on its next event-loop turn,
        -- after this coroutine has installed its timer.
        ready:post()
        ngx.sleep(10)
        error("exited coroutine resumed")
    end

    local co = coroutine.create(sleep)
    local ok, err = coroutine.resume(co, depth - 1)
    assert(ok, err)
end

-- Cross the initial four-element user_co_ctx list allocation.
sleep(6)
_EOC_

add_block_preprocessor(sub {
    my $block = shift;

    $block->set_value("user_files", $Helpers);
});

run_tests();

__DATA__

=== TEST 1: client abort cleans an ordinary coroutine sleep in content
--- stream_config
    lua_shared_dict coroutine_cleanup 1m;
    server {
        listen unix:$TEST_NGINX_HTML_DIR/victim.sock;
        lua_check_client_abort on;
        content_by_lua_file html/sleep.lua;
        log_by_lua_block {
            assert(ngx.shared.coroutine_cleanup:set("finished", true))
        }
    }
--- stream_server_config
    content_by_lua_file html/abort.lua;
--- stream_response
client abort cleanup: OK
--- grep_error_log eval: qr/lua clean up the timer for pending ngx\.sleep/
--- grep_error_log_out
lua clean up the timer for pending ngx.sleep
--- no_error_log
[error]
[alert]



=== TEST 2: client abort cleans an ordinary coroutine sleep in preread
--- stream_config
    lua_shared_dict coroutine_cleanup 1m;
    server {
        listen unix:$TEST_NGINX_HTML_DIR/victim.sock;
        lua_check_client_abort on;
        preread_by_lua_file html/sleep.lua;
        content_by_lua_block {
            error("aborted session reached content phase")
        }
        log_by_lua_block {
            assert(ngx.shared.coroutine_cleanup:set("finished", true))
        }
    }
--- stream_server_config
    content_by_lua_file html/abort.lua;
--- stream_response
client abort cleanup: OK
--- grep_error_log eval: qr/lua clean up the timer for pending ngx\.sleep/
--- grep_error_log_out
lua clean up the timer for pending ngx.sleep
--- no_error_log
[error]
[alert]



=== TEST 3: content exit cleans a sleep under six ordinary coroutines
--- stream_config
    lua_package_path "../lua-resty-core/lib/?.lua;../lua-resty-lrucache/lib/?.lua;;";
--- stream_server_config
    content_by_lua_file html/exit.lua;
--- stream_response
request exit cleanup: OK
--- grep_error_log eval: qr/lua clean up the timer for pending ngx\.sleep/
--- grep_error_log_out
lua clean up the timer for pending ngx.sleep
--- no_error_log
[error]
[alert]



=== TEST 4: preread exit cleans a sleep under six ordinary coroutines
--- stream_config
    lua_package_path "../lua-resty-core/lib/?.lua;../lua-resty-lrucache/lib/?.lua;;";
--- stream_server_config
    preread_by_lua_file html/exit.lua;
    content_by_lua_block {
        error("exited session reached content phase")
    }
--- stream_response
request exit cleanup: OK
--- grep_error_log eval: qr/lua clean up the timer for pending ngx\.sleep/
--- grep_error_log_out
lua clean up the timer for pending ngx.sleep
--- no_error_log
[error]
[alert]
