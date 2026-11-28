use Test::Nginx::Socket::Lua::Stream;

repeat_each(1);
plan tests => blocks() * 3;

run_tests();

__DATA__

=== TEST 1: an explicit host:port pool shares the default pool
--- stream_server_config
    content_by_lua_block {
        local port = $TEST_NGINX_SERVER_PORT
        local sock = ngx.socket.tcp()
        assert(sock:connect(table.concat({127, 0, 0, 1}, "."), port))
        ngx.say(sock:getreusedtimes())
        assert(sock:setkeepalive())

        sock = ngx.socket.tcp()
        assert(sock:connect("127.0.0.1", port, {pool = "127.0.0.1:" .. port}))
        ngx.say(sock:getreusedtimes())
        assert(sock:close())
    }
--- stream_response
0
1
--- no_error_log
[error]
