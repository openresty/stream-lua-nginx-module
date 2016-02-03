# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;
#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 3);

#no_diff();
#no_long_string();
#master_on();
#workers(2);
run_tests();

__DATA__

=== TEST 1: pid
--- stream_server_config
    content_by_lua_block {
        local pid = ngx.var.pid
        ngx.say("variable pid: ", pid)
        if pid ~= tostring(ngx.worker.pid()) then
            ngx.say("variable pid is wrong.")
        else
            ngx.say("variable pid is correct.")
        end
    }
--- stream_response_like
variable pid: \d+
variable pid is correct\.
--- no_error_log
[error]



=== TEST 2: remote_addr
--- stream_server_config
    content_by_lua_block {
        ngx.say("remote_addr: ", ngx.var.remote_addr)
        ngx.say("type: ", type(ngx.var.remote_addr))
    }
--- stream_response
remote_addr: 127.0.0.1
type: string



=== TEST 3: binary_remote_addr
--- stream_server_config
    content_by_lua_block {
        ngx.say("binary_remote_addr len: ", #ngx.var.binary_remote_addr)
        ngx.say("type: ", type(ngx.var.binary_remote_addr))
    }
--- stream_response
binary_remote_addr len: 4
type: string



=== TEST 4: server_addr & server_port
--- stream_server_config
    content_by_lua_block {
        ngx.say("server_addr: ", ngx.var.server_addr)
        ngx.say("server_port: ", ngx.var.server_port)
        ngx.say(type(ngx.var.server_addr))
        ngx.say(type(ngx.var.server_port))
    }
--- stream_response
server_addr: 127.0.0.1
server_port: 1985
string
string



=== TEST 5: connection & nginx_version
--- stream_server_config
    content_by_lua_block {
        ngx.say("connection: ", ngx.var.connection)
        ngx.say("nginx_version: ", ngx.var.nginx_version)
        ngx.say(type(ngx.var.connection))
        ngx.say(type(ngx.var.nginx_version))
    }
--- stream_response_like
connection: \d
nginx_version: [.\w]+
string
string



=== TEST 6: reference nonexistent variable
--- stream_server_config
    content_by_lua_block {
        ngx.say("value: ", ngx.var.notfound)
    }
--- stream_response
value: nil



=== TEST 7: variable name is *not* caseless
--- stream_server_config
    content_by_lua_block {
        ngx.say("value: ", ngx.var.REMOTE_ADDR)
    }
--- stream_response
value: nil



=== TEST 8: get a bad variable name
--- stream_server_config
    content_by_lua_block {
        ngx.say("value: ", ngx.var[true])
    }
--- stream_response
--- error_log
bad variable name



=== TEST 9: can not set variable
--- stream_server_config
    content_by_lua_block {
        ngx.var.foo = 56
    }
--- stream_response
--- error_log
can not set variable
