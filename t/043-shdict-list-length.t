use Test::Nginx::Socket::Lua::Stream;

repeat_each(1);
master_on();
workers(2);
plan tests => blocks() * 3;

run_tests();

__DATA__

=== TEST 1: concurrent pushes return each list length exactly once
--- stream_config
    lua_shared_dict lists 1m;
    init_worker_by_lua_block {
        local function push()
            local d = ngx.shared.lists
            local id = ngx.worker.id()
            assert(d:incr("ready", 1, 0))
            while d:get("ready") < 2 do
                ngx.sleep(0.001)
            end

            local push_item = id == 0 and d.lpush or d.rpush
            for i = 1, 1000 do
                local n = assert(push_item(d, "list", i))
                assert(d:add("seen:" .. n, true))
                assert(d:llen("list") >= n)
            end

            assert(d:incr("done", 1, 0))
        end

        assert(ngx.timer.at(0, push))
    }
--- stream_server_config
    content_by_lua_block {
        local d = ngx.shared.lists
        local deadline = ngx.now() + 2
        while d:get("done") ~= 2 do
            assert(ngx.now() < deadline, "workers did not finish")
            ngx.sleep(0.001)
        end

        for i = 1, 2000 do
            assert(d:get("seen:" .. i))
        end
        ngx.say(d:llen("list"))
    }
--- stream_response
2000
--- no_error_log
[error]
