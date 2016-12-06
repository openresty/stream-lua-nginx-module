# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;
use Cwd qw(cwd);
#worker_connections(1014);
#master_on();
#workers(2);
log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

my $pwd = cwd();

our $HttpConfig = qq{
    server {
        listen 12355;
        location = / {
            content_by_lua_block {
                ngx.sleep(20)
                ngx.say('foo');
            }
        }
    }
};

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: log socket errors off (tcp)
--- http_config eval: $::HttpConfig
--- stream_server_config
    lua_socket_read_timeout 1ms;
    lua_socket_log_errors off;
    content_by_lua_block {
            local sock = ngx.socket.tcp()
            local ok, err = sock:connect("127.0.0.1", 12355)
            if not ok then
                ngx.say("can not connect")
            end

            local line, err, partial = sock:receive()
            ngx.say(err)
    }

--- config
--- stream_response
timeout
--- no_error_log
[error]



=== TEST 2: log socket errors on (tcp)
--- http_config eval: $::HttpConfig
--- stream_server_config
    lua_socket_read_timeout 1ms;
    lua_socket_log_errors on;
    content_by_lua_block {
            local sock = ngx.socket.tcp()
            local ok, err = sock:connect("127.0.0.1", 12355)
            if not ok then
                ngx.say("can not connect")
            end

            local line, err, partial = sock:receive()
            ngx.say(err)
    }

--- config
--- stream_response
timeout
--- error_log
lua tcp socket read timed out



=== TEST 3: log socket errors on (udp)
--- http_config eval: $::HttpConfig
--- stream_server_config
    lua_socket_log_errors on;
    lua_socket_read_timeout 1ms;
    content_by_lua_block {
            local sock = ngx.socket.udp()
            local ok, err = sock:setpeername("127.0.0.1", 12355)
            ok, err = sock:receive()
            ngx.say(err)
    }

--- config
--- stream_response
timeout
--- error_log
lua udp socket read timed out



=== TEST 4: log socket errors off (udp)
--- http_config eval: $::HttpConfig
--- stream_server_config
    lua_socket_log_errors off;
    lua_socket_read_timeout 1ms;
    content_by_lua_block {
            local sock = ngx.socket.udp()
            local ok, err = sock:setpeername("127.0.0.1", 12355)
            ok, err = sock:receive()
            ngx.say(err)
    }

--- config
--- stream_response
timeout
--- no_error_log
[error]
