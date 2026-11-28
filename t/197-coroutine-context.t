use Test::Nginx::Socket::Lua::Stream;

repeat_each(1);
plan tests => blocks() * 3;

run_tests();

__DATA__

=== TEST 1: timer sees only coroutines belonging to its request
--- stream_server_config
    content_by_lua_block {
        local done = require("ngx.semaphore").new()
        local status
        local co = coroutine.create(function() return "resumed" end)
        assert(ngx.timer.at(0, function()
            status = coroutine.status(co)
            done:post()
        end))
        assert(done:wait(1))
        ngx.say(status)
        ngx.say(coroutine.status(co))
        local ok, value = coroutine.resume(co)
        assert(ok, value)
        ngx.say(value)
    }
--- stream_response
dead
suspended
resumed
--- no_error_log
[error]
