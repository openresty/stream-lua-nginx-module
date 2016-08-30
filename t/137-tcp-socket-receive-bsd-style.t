
use Test::Nginx::Socket::Lua::Stream 'no_plan';

repeat_each(10);

run_tests();

__DATA__

=== TEST 1: *b pattern for receive
--- config
    location = /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            sock:settimeout(100)
            assert(sock:connect("127.0.0.1", 5678))
            sock:send("10")
            ngx.sleep(0.01)
            sock:send("2")
            ngx.sleep(0.01)
            sock:send("4")

            local pow, _ = sock:receive('*l')
            sock:close()
            ngx.say(pow)
        }
    }
--- main_config
    stream {
        server {
            listen 5678;
            content_by_lua_block {
                local function is_power_of_two(str)
                    local num = tonumber(str)
                    if num <= 0 then
                        return false, nil 
                    end 
                    local power = 0 
                    while num ~= 1 do
                        if math.fmod(num, 2) ~= 0 then
                            return false, nil 
                        end 
                        num = num / 2 
                        power = power + 1 
                    end 
                    return true, power
                end

                local sock = ngx.req.socket(true)
                local msg = ''
                local pow
                while true do
                    local chunk, err = sock:receive('*b')
                    if not chunk then
                        break
                    end
                    msg = msg .. chunk
                    local ok, num = is_power_of_two(msg)
                    if ok then
                        pow = num
                        break
                    end
                end
                sock:send(tostring(pow) .. '\n')
            }
        }
    }

--- request
GET /t
--- response_body
10
