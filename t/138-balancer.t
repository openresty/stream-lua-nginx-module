# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 4 + 8);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: simple logging
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
        }
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- error_log eval
[
'[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "http://0\.0\.0\.1:80/t"},
]
--- no_error_log
[warn]



=== TEST 2: exit 403
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
            ngx.exit(403)
        }
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- error_log
[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,
--- no_error_log eval
[
'[warn]',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "http://0\.0\.0\.1:80/t"},
]



=== TEST 3: exit OK
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
            ngx.exit(ngx.OK)
        }
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- error_log eval
[
'[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "http://0\.0\.0\.1:80/t"},
]
--- no_error_log
[warn]



=== TEST 4: ngx.var works
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            print("1: variable foo = ", ngx.var.foo)
            ngx.var.foo = tonumber(ngx.var.foo) + 1
            print("2: variable foo = ", ngx.var.foo)
        }
    }
--- stream_server_config
    set $foo 32;
    proxy_pass backend;
--- stream_response
--- error_log eval
[
"1: variable foo = 32",
"2: variable foo = 33",
qr/\[crit\] .* connect\(\) .*? failed/,
]
--- no_error_log
[warn]



=== TEST 5: ngx.req.get_headers works
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            print("header foo: ", ngx.req.get_headers()["foo"])
        }
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- error_log eval
[
"header foo: bar",
qr/\[crit\] .* connect\(\) .*? failed/,
]
--- no_error_log
[warn]



=== TEST 6: ngx.req.get_uri_args() works
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            print("arg foo: ", ngx.req.get_uri_args()["foo"])
        }
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- error_log eval
["arg foo: bar",
qr/\[crit\] .* connect\(\) .*? failed/,
]
--- no_error_log
[warn]



=== TEST 7: ngx.req.get_method() works
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            print("method: ", ngx.req.get_method())
        }
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- error_log eval
[
"method: GET",
qr/\[crit\] .* connect\(\) .*? failed/,
]
--- no_error_log
[warn]



=== TEST 8: simple logging (by_lua_file)
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_file html/a.lua;
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- error_log eval
[
'[lua] a.lua:1: hello from balancer by lua! while connecting to upstream,',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "http://0\.0\.0\.1:80/t"},
]
--- no_error_log
[warn]



=== TEST 9: cosockets are disabled
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            local sock, err = ngx.socket.tcp()
        }
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- error_log eval
qr/\[error\] .*? failed to run balancer_by_lua\*: balancer_by_lua:2: API disabled in the context of balancer_by_lua\*/



=== TEST 10: ngx.sleep is disabled
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            ngx.sleep(0.1)
        }
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- error_log eval
qr/\[error\] .*? failed to run balancer_by_lua\*: balancer_by_lua:2: API disabled in the context of balancer_by_lua\*/



=== TEST 11: get_phase
--- stream_config
    upstream backend {
        server 0.0.0.1;
        balancer_by_lua_block {
            print("I am in phase ", ngx.get_phase())
        }
    }
--- stream_server_config
    proxy_pass backend;
--- stream_response
--- grep_error_log eval: qr/I am in phase \w+/
--- grep_error_log_out
I am in phase balancer
--- error_log eval
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "http://0\.0\.0\.1:80/t"}
--- no_error_log
[error]
