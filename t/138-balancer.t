# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2 + 4);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: simple logging
--- stream_config
    upstream backend {
        server 0.0.0.1:80;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
        }
    }
--- stream_server_config
    proxy_pass backend;
--- error_log eval
[
'[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "0\.0\.0\.1:80"},
]



=== TEST 2: simple logging (by_lua_file)
--- stream_config
    upstream backend {
        server 0.0.0.1:80;
        balancer_by_lua_file html/a.lua;
    }
--- stream_server_config
    proxy_pass backend;
--- user_files
>>> a.lua
print("hello from balancer by lua!")
--- error_log eval
[
'[lua] a.lua:1: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "0\.0\.0\.1:80"},
]



=== TEST 3: cosockets are disabled
--- stream_config
    upstream backend {
        server 0.0.0.1:80;
        balancer_by_lua_block {
            local sock, err = ngx.socket.tcp()
        }
    }
--- stream_server_config
    proxy_pass backend;
--- error_log eval
qr/\[error\] .*? failed to run balancer_by_lua\*: balancer_by_lua:2: API disabled in the context of balancer_by_lua\*/



=== TEST 4: ngx.exit ERROR works
--- stream_config
    upstream backend {
        server 0.0.0.1:80;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
            ngx.exit(ngx.ERROR)
        }
    }
--- stream_server_config
    proxy_pass backend;
--- error_log
[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream



=== TEST 5: ngx.exit OK works
--- stream_config
    upstream backend {
        server 0.0.0.1:80;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
            ngx.exit(ngx.OK)
        }
    }
--- stream_server_config
    proxy_pass backend;
--- error_log eval
[
'[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "0\.0\.0\.1:80"},
]



=== TEST 6: ngx.sleep is disabled
--- stream_config
    upstream backend {
        server 0.0.0.1:80;
        balancer_by_lua_block {
            ngx.sleep(0.1)
        }
    }
--- stream_server_config
    proxy_pass backend;
--- error_log eval
qr/\[error\] .*? failed to run balancer_by_lua\*: balancer_by_lua:2: API disabled in the context of balancer_by_lua\*/



=== TEST 7: get_phase
--- stream_config
    upstream backend {
        server 0.0.0.1:80;
        balancer_by_lua_block {
            print("I am in phase ", ngx.get_phase())
        }
    }
--- stream_server_config
    proxy_pass backend;
--- grep_error_log eval: qr/I am in phase \w+/
--- grep_error_log_out
I am in phase balancer
--- error_log eval
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "0\.0\.0\.1:80"}
