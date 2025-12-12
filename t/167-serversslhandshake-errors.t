# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4 + 25);

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: serversslhandshake - error handling without SSL configured
--- stream_server_config
    content_by_lua_block {
        local sock = assert(ngx.req.socket(true))
        sock:settimeout(3000)
        ngx.log(ngx.INFO, "received socket")

        -- Consume the initial test line
        local line, err = sock:receive()
        if not line then
            ngx.log(ngx.ERR, "failed to receive: ", err)
            return
        end
        ngx.log(ngx.INFO, "received initial line: ", line)

        -- Try to do SSL handshake without SSL configured (should fail)
        ngx.log(ngx.INFO, "calling serversslhandshake without SSL")
        local session, err = sock:serversslhandshake()
        ngx.log(ngx.INFO, "serversslhandshake returned")

        if not session then
            ngx.log(ngx.WARN, "serversslhandshake failed: ", err)
            if err == "ssl not configured for this server" then
                ngx.log(ngx.WARN, "confirmed: correct error for no SSL config")
            end
            ngx.say("handshake failed: ", err)
        else
            ngx.log(ngx.ERR, "unexpected: handshake succeeded")
            ngx.say("handshake succeeded")
        end
    }

--- stream_request
test
--- stream_response
handshake failed: ssl not configured for this server
--- error_log
received socket
received initial line: test
calling serversslhandshake without SSL
serversslhandshake returned
serversslhandshake failed: ssl not configured for this server
confirmed: correct error for no SSL config
--- no_error_log
[alert]
unexpected: handshake succeeded



=== TEST 2: serversslhandshake - client aborts during handshake
--- stream_config
    server {
        listen $TEST_NGINX_RAND_PORT_1;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            sock:settimeout(3000)
            ngx.log(ngx.INFO, "received socket")

            -- Consume the initial test line
            local line, err = sock:receive()
            if not line then
                ngx.log(ngx.ERR, "failed to receive: ", err)
                return
            end
            ngx.log(ngx.INFO, "received initial line: ", line)

            -- Send response line
            sock:send("ok\n")
            ngx.log(ngx.INFO, "sent ok response")

            ngx.log(ngx.INFO, "calling serversslhandshake")
            local session, err = sock:serversslhandshake()
            ngx.log(ngx.INFO, "serversslhandshake returned")

            if not session then
                ngx.log(ngx.WARN, "handshake failed: ", err)
                ngx.say("handshake failed: ", err)
            else
                ngx.log(ngx.ERR, "unexpected handshake success")
                ngx.say("handshake success")
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeout(3000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_RAND_PORT_1)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        -- Send initial test line
        sock:send("test\n");

        -- Receive ok response
        local line, err = sock:receive()
        if not line then
            ngx.say("failed to receive ok response: ", err)
            return
        end

        -- Send partial SSL handshake (Client Hello header only)
        sock:send("\x16\x03\x01\x00\x05")

        -- Immediately close without completing handshake
        sock:close()
        ngx.say("client aborted")
    }

--- stream_response
connected: 1
client aborted

--- error_log
received socket
received initial line: test
sent ok response
calling serversslhandshake
serversslhandshake returned
handshake failed: handshake failed

--- no_error_log
[alert]
unexpected handshake success



=== TEST 3: serversslhandshake - immediate close after successful handshake
--- stream_config
    server {
        listen $TEST_NGINX_RAND_PORT_1;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            sock:settimeout(3000)
            ngx.log(ngx.INFO, "received socket")

            -- Consume the initial test line
            local line, err = sock:receive()
            if not line then
                ngx.log(ngx.ERR, "failed to receive: ", err)
                return
            end
            ngx.log(ngx.INFO, "received initial line: ", line)

            -- Send response line
            sock:send("ok\n")
            ngx.log(ngx.INFO, "sent ok response")

            ngx.log(ngx.INFO, "calling serversslhandshake")
            local session, err = sock:serversslhandshake()

            if not session then
                ngx.log(ngx.ERR, "handshake failed: ", err)
                ngx.say("handshake failed: ", err)
                return
            end

            ngx.log(ngx.INFO, "handshake success, protocol: ", session.protocol)
            ngx.say("handshake success")

            -- Try to read after handshake
            sock:settimeout(1000)
            ngx.log(ngx.INFO, "attempting read after handshake")
            local line, err = sock:receive()
            if not line then
                ngx.log(ngx.WARN, "read failed (expected): ", err)
                ngx.say("read after handshake: ", err)
            else
                ngx.log(ngx.INFO, "read line: ", line)
                ngx.say("read: ", line)
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeout(3000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_RAND_PORT_1)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        -- Send initial test line
        sock:send("test\n");

        -- Receive ok response
        local line, err = sock:receive()
        if not line then
            ngx.say("failed to receive ok response: ", err)
            return
        end

        -- Perform client SSL handshake
        local session, err = sock:sslhandshake(false, nil, false)
        if not session then
            ngx.say("client handshake failed: ", err)
            return
        end

        ngx.say("client handshake: success")

        -- Immediately close after handshake
        sock:close()
        ngx.say("client closed immediately")
    }

--- stream_response
connected: 1
client handshake: success
client closed immediately

--- error_log
received socket
received initial line: test
sent ok response
calling serversslhandshake
handshake success, protocol: TLS
attempting read after handshake
read failed (expected): closed

--- no_error_log
[alert]
handshake failed:



=== TEST 4: serversslhandshake - multiple calls should handle gracefully
--- stream_config
    server {
        listen $TEST_NGINX_RAND_PORT_1;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            sock:settimeout(3000)

            ngx.log(ngx.INFO, "calling first serversslhandshake")
            -- First handshake
            local session1, err = sock:serversslhandshake()
            if not session1 then
                ngx.log(ngx.ERR, "first handshake failed: ", err)
                return
            end

            ngx.log(ngx.INFO, "first handshake success, protocol: ", session1.protocol)

            -- Try second handshake (should return existing session)
            ngx.log(ngx.INFO, "calling second serversslhandshake")
            local session2, err = sock:serversslhandshake()
            if not session2 then
                ngx.log(ngx.ERR, "second handshake failed: ", err)
                return
            end

            ngx.log(ngx.INFO, "second handshake success, same protocol: ",
                    tostring(session1.protocol == session2.protocol))

            -- Verify we can still communicate
            ngx.log(ngx.INFO, "attempting communication after multiple handshakes")
            local line, err = sock:receive()
            if line then
                ngx.log(ngx.INFO, "received line, sending response")
                sock:send(line:upper() .. "\n")
            else
                ngx.log(ngx.WARN, "failed to receive: ", err)
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeout(3000)

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_RAND_PORT_1)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        -- Client handshake
        local session, err = sock:sslhandshake(false, nil, false)
        if not session then
            ngx.say("client handshake failed: ", err)
            return
        end

        ngx.say("client handshake: success")

        -- Send test line
        sock:send("hello\n")
        local line, err = sock:receive()
        ngx.say("response: ", line)

        sock:close()
    }

--- stream_response
connected: 1
client handshake: success
response: HELLO

--- error_log
calling first serversslhandshake
first handshake success, protocol: TLS
calling second serversslhandshake
second handshake success, same protocol: true
attempting communication after multiple handshakes
received line, sending response

--- no_error_log
[error]
[alert]
