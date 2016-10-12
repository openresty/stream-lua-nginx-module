# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream 'no_plan';
#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

#plan tests => repeat_each() * (blocks() * 4 + 9);

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
--- no_error_log
[warn]



=== TEST 2: exit 403
--- stream_config
    upstream backend {
        server 0.0.0.1:80;
        balancer_by_lua_block {
            print("hello from balancer by lua!")
            ngx.exit(403)
        }
    }
--- stream_server_config
        proxy_pass backend;
--- error_log
[lua] balancer_by_lua:2: hello from balancer by lua! while connecting to upstream,
--- no_error_log eval
[
'[warn]',
'[error]',
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "0\.0\.0\.1:80"},
]



=== TEST 3: exit OK
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
--- no_error_log
[warn]



=== TEST 4: ngx.var works
--- stream_config
    upstream backend {
        server 0.0.0.1:80;
        balancer_by_lua_block {
            print("pid = ", ngx.var.pid)
        }
    }
--- stream_server_config
        proxy_pass backend;
--- error_log eval
[
qr{pid = \d+},
qr{\[crit\] .*? connect\(\) to 0\.0\.0\.1:80 failed .*?, upstream: "0\.0\.0\.1:80"},
]
--- no_error_log
[warn]



=== TEST 5: simple logging (by_lua_file)
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
--- no_error_log
[warn]



=== TEST 6: cosockets are disabled
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



=== TEST 7: ngx.sleep is disabled
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



=== TEST 8: get_phase
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
--- no_error_log
[error]



=== TEST 9: code cache off
--- stream_config
    lua_package_path "t/servroot/html/?.lua;;";

    lua_code_cache off;

    upstream backend {
        server 127.0.0.1:1989;
        balancer_by_lua_block {
            if not package.loaded.me then
                package.loaded.me = 0
            end

            package.loaded.me = package.loaded.me + 1

            ngx.log(ngx.NOTICE, "me: ", package.loaded.me)
        }
    }

    server {
        listen 1989;

        content_by_lua_block {
            ngx.say("ok")
        }
    }
--- stream_server_config
        proxy_pass backend;
--- stream_response
ok
--- grep_error_log eval: qr/\bme: \w+/
--- grep_error_log_out
me: 1
--- no_error_log
[error]
