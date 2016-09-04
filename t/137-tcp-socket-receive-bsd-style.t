# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream 'no_plan';

repeat_each(2);

log_level 'debug';

run_tests();

__DATA__

=== TEST 1: *b pattern for receive
--- config
    location = /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:settimeout(100)
            assert(sock:connect("127.0.0.1", 5678))

            sock:send("1")
            ngx.sleep(0.01)

            sock:send("22")
            ngx.sleep(0.01)

            local t = {
                'test',
                'send',
                'table',
            }
            sock:send(t)
            ngx.sleep(0.01)

            sock:send("hello world")

            local data, _ = sock:receive('*a')
            ngx.say(data)

            sock:close()
        }
    }
--- main_config
    stream {
        server {
            listen 5678;
            content_by_lua_block {
                local sock = ngx.req.socket(true)
                local data, _ = sock:receive('*b')
                if data ~= '1' then
                    ngx.log(ngx.ERR, "unexcepted result of: ", data)
                    return
                end

                data, _ = sock:receive('*b')
                if data ~= '22' then
                    ngx.log(ngx.ERR, "unexcepted result of: ", data)
                    return
                end

                data, _ = sock:receive('*b')
                if data ~= 'testsendtable' then
                    ngx.log(ngx.ERR, "unexcepted result of: ", data)
                    return
                end

                data, _ = sock:receive('*b')
                if data ~= 'hello world' then
                    ngx.log(ngx.ERR, "unexcepted result of: ", data)
                    return
                end

                sock:send('ok')
            }
        }
    }

--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
--- error_log
stream lua tcp socket read bsd
