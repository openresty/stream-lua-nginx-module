# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * 7;

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: serversslhandshake without SSL configured should fail
--- stream_server_config
    content_by_lua_block {
        local sock, err = ngx.req.socket(true)
        if not sock then
            ngx.say("failed to get socket: ", err)
            return
        end

        -- Consume the initial test line
        local line, err = sock:receive()
        if not line then
            ngx.say("failed to receive: ", err)
            return
        end

        ngx.say("method exists: ", type(sock.serversslhandshake) == "function")

        local session, err = sock:serversslhandshake()
        ngx.say("error: ", err or "unexpected success")
    }

--- stream_request
test
--- stream_response
method exists: true
error: ssl not configured for this server
--- no_error_log
[alert]



=== TEST 2: serversslhandshake method doesn't exist on non-downstream socket
--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        ngx.say("method exists: ", type(sock.serversslhandshake) == "function")
    }

--- stream_response
method exists: false
--- no_error_log
[error]
[alert]


