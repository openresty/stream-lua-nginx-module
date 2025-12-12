# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 9);

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: STARTTLS - plaintext to SSL upgrade
--- stream_config
    server {
        listen $TEST_NGINX_RAND_PORT_1;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))

            -- Send plaintext banner
            sock:send("220 Ready\n")

            -- Get STARTTLS command
            local data = sock:receive()
            if data == "STARTTLS" then
                sock:send("220 Go ahead\n")

                -- Perform server-side SSL handshake
                local session, err = sock:serversslhandshake()
                if not session then
                    ngx.log(ngx.ERR, "SSL handshake failed: ", err)
                    return
                end

                -- Log session info
                ngx.log(ngx.INFO, "SSL session protocol=", session.protocol);
                ngx.log(ngx.INFO, "SSL session cipher=", session.cipher);
                ngx.log(ngx.INFO, "SSL session session_reused=", session.session_reused);

                -- Now encrypted
                data = sock:receive()
                if data == "PING" then
                    sock:send("PONG\n")
                end
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        do
            local sock = ngx.socket.tcp()
            sock:settimeout(3000)
            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_RAND_PORT_1)
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            -- Get plaintext banner
            local line, err = sock:receive()
            ngx.say("banner: ", line)

            -- Send STARTTLS
            sock:send("STARTTLS\n")
            line, err = sock:receive()
            ngx.say("response: ", line)

            -- Client SSL handshake (disable session reuse and SNI)
            local session, err = sock:sslhandshake(false, nil, false)
            if not session then
                ngx.say("handshake failed: ", err)
                return
            end

            ngx.say("handshake: success")

            -- Send encrypted
            sock:send("PING\n")
            line, err = sock:receive()
            ngx.say("encrypted: ", line)

            sock:close()
        end
        collectgarbage()
    }

--- stream_response
connected: 1
banner: 220 Ready
response: 220 Go ahead
handshake: success
encrypted: PONG

--- error_log
SSL session protocol=TLS
SSL session cipher=
SSL session session_reused=false
--- no_error_log
[error]
[alert]



=== TEST 2: STARTTLS - timeout during handshake
--- stream_config
    server {
        listen $TEST_NGINX_RAND_PORT_1;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))

            -- Send plaintext banner
            sock:send("220 Ready\n")

            -- Get STARTTLS command
            local data = sock:receive()
            if data == "STARTTLS" then
                sock:send("220 Go ahead\n")

                -- Perform server-side SSL handshake with timeout
                sock:settimeout(100)  -- 100ms timeout
                ngx.log(ngx.INFO, "calling serversslhandshake with 100ms timeout")
                local session, err = sock:serversslhandshake()

                if not session then
                    ngx.log(ngx.WARN, "SSL handshake failed as expected: ", err)
                    if err == "timeout" then
                        ngx.log(ngx.WARN, "confirmed: got timeout error")
                    end
                else
                    ngx.log(ngx.ERR, "unexpected: handshake succeeded")
                end
            end
            sock:close()
        }
    }

--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()

        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_RAND_PORT_1)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        ngx.say("connected: ", ok)

        -- Get plaintext banner
        local line, err = sock:receive()
        ngx.say("banner: ", line)

        -- Send STARTTLS
        sock:send("STARTTLS\n")
        line, err = sock:receive()
        ngx.say("response: ", line)

        -- Client pauses instead of doing SSL handshake
        ngx.log(ngx.INFO, "client pausing for 1 second instead of handshaking")
        ngx.sleep(1)
        ngx.log(ngx.INFO, "client done sleeping")

        -- Connection should be closed by server
        line, err = sock:receive()
        ngx.say("client got receive error: " .. err)

        -- Connection will be closed by server after timeout
        ngx.say("client finished")

        sock:close()
    }

--- stream_response
connected: 1
banner: 220 Ready
response: 220 Go ahead
client got receive error: closed
client finished

--- error_log
calling serversslhandshake with 100ms timeout
SSL handshake failed as expected: timeout
confirmed: got timeout error
client pausing for 1 second instead of handshaking
client done sleeping

--- no_error_log
[alert]
