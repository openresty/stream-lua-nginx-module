use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

add_block_preprocessor(sub {
    my $block = shift;

    if (!defined $block->no_error_log) {
        $block->set_value("no_error_log", "[error]");
    }
});

no_long_string();
run_tests();

__DATA__

=== TEST 1: lua_load_resty_core is enabled by default
--- stream_server_config
    content_by_lua_block {
        local loaded_resty_core = package.loaded["resty.core"]
        local resty_core = require "resty.core"

        ngx.say("resty.core loaded: ", loaded_resty_core == resty_core)
    }
--- stream_response
resty.core loaded: true



=== TEST 2: lua_load_resty_core can be disabled
--- stream_config
    lua_load_resty_core off;
--- stream_server_config
    content_by_lua_block {
        local loaded_resty_core = package.loaded["resty.core"]

        ngx.say("resty.core loaded: ", loaded_resty_core ~= nil)
    }
--- stream_response
resty.core loaded: false



=== TEST 3: lua_load_resty_core is effective when using lua_shared_dict
--- stream_config
    lua_shared_dict dogs 128k;
--- stream_server_config
    content_by_lua_block {
        local loaded_resty_core = package.loaded["resty.core"]
        local resty_core = require "resty.core"

        ngx.say("resty.core loaded: ", loaded_resty_core == resty_core)
    }
--- stream_response
resty.core loaded: true



=== TEST 4: lua_load_resty_core 'on' in stream block and 'off' in http block
--- http_config
    lua_load_resty_core off;
--- config
    location = /t2 {
        content_by_lua_block {
            local loaded_resty_core = package.loaded["resty.core"]

            local msg = "resty.core loaded in http: " .. tostring(loaded_resty_core ~= nil)
            ngx.header["Content-Length"] = #msg
            ngx.say(msg)
        }
    }
--- stream_server_config
    content_by_lua_block {
        local loaded_resty_core = package.loaded["resty.core"]
        local resty_core = require "resty.core"

        ngx.say("resty.core loaded in stream: ", loaded_resty_core == resty_core)

        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local req = "GET /t2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        local cl

        while true do
            local line, err, part = sock:receive("*l")
            if err then
                ngx.say("failed to receive headers: ", err, " [", part, "]")
                break
            end

            local k, v = line:match("([^:]*):%s*(.*)")
            if k == "Content-Length" then
                cl = v
            end

            if line == "" then
                local body, err = sock:receive(cl)
                if err then
                    ngx.say("failed to receive body: ", err)
                    break
                end

                ngx.say(body)
                break
            end
        end

        ok, err = sock:close()
    }
--- stream_response
resty.core loaded in stream: true
resty.core loaded in http: false



=== TEST 5: lua_load_resty_core 'off' in stream block and 'on' in http block
--- config
    location = /t2 {
        content_by_lua_block {
            local loaded_resty_core = package.loaded["resty.core"]
            local resty_core = require "resty.core"

            local msg = "resty.core loaded in http: " .. tostring(loaded_resty_core == resty_core)
            ngx.header["Content-Length"] = #msg
            ngx.say(msg)
        }
    }
--- stream_config
    lua_load_resty_core off;
--- stream_server_config
    content_by_lua_block {
        local loaded_resty_core = package.loaded["resty.core"]

        ngx.say("resty.core loaded in stream: ", loaded_resty_core ~= nil)

        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local req = "GET /t2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        local cl

        while true do
            local line, err, part = sock:receive("*l")
            if err then
                ngx.say("failed to receive headers: ", err, " [", part, "]")
                break
            end

            local k, v = line:match("([^:]*):%s*(.*)")
            if k == "Content-Length" then
                cl = v
            end

            if line == "" then
                local body, err = sock:receive(cl)
                if err then
                    ngx.say("failed to receive body: ", err)
                    break
                end

                ngx.say(body)
                break
            end
        end

        ok, err = sock:close()
    }
--- stream_response
resty.core loaded in stream: false
resty.core loaded in http: true



=== TEST 6: lua_load_resty_core 'off' in stream block and 'off' in http block
--- http_config
    lua_load_resty_core off;
--- config
    location = /t2 {
        content_by_lua_block {
            local loaded_resty_core = package.loaded["resty.core"]

            local msg = "resty.core loaded in http: " .. tostring(loaded_resty_core ~= nil)
            ngx.header["Content-Length"] = #msg
            ngx.say(msg)
        }
    }
--- stream_config
    lua_load_resty_core off;
--- stream_server_config
    content_by_lua_block {
        local loaded_resty_core = package.loaded["resty.core"]

        ngx.say("resty.core loaded in stream: ", loaded_resty_core ~= nil)

        local sock = ngx.socket.tcp()
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local req = "GET /t2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

        local bytes, err = sock:send(req)
        if not bytes then
            ngx.say("failed to send request: ", err)
            return
        end

        local cl

        while true do
            local line, err, part = sock:receive("*l")
            if err then
                ngx.say("failed to receive headers: ", err, " [", part, "]")
                break
            end

            local k, v = line:match("([^:]*):%s*(.*)")
            if k == "Content-Length" then
                cl = v
            end

            if line == "" then
                local body, err = sock:receive(cl)
                if err then
                    ngx.say("failed to receive body: ", err)
                    break
                end

                ngx.say(body)
                break
            end
        end

        ok, err = sock:close()
    }
--- stream_response
resty.core loaded in stream: false
resty.core loaded in http: false
