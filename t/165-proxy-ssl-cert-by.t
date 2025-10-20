# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
repeat_each(3);

# All these tests need to have new openssl
my $NginxBinary = $ENV{'TEST_NGINX_BINARY'} || 'nginx';
my $openssl_version = eval { `$NginxBinary -V 2>&1` };

if ($openssl_version =~ m/built with OpenSSL (0|1\.0\.(?:0|1[^\d]|2[a-d]).*)/) {
    plan(skip_all => "too old OpenSSL, need >= 1.0.2e, was $1");
} else {
    plan tests => repeat_each() * (blocks() * 5 + 22);
}

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();

run_tests();

__DATA__

=== TEST 1: without proxy_ssl on
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;

    proxy_ssl_certificate_by_lua_block {
        ngx.log(ngx.INFO, "hello world")
    }
--- error_log
proxy_ssl_certificate_by_lua* should be used with proxy_ssl directive
--- no_error_log
[error]
[alert]
--- must_die



=== TEST 2: proxy_ssl_certificate_by_lua in stream {} block
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        return 'it works!\n';
    }

    proxy_ssl_certificate_by_lua_block {
        ngx.log(ngx.INFO, "hello world")
    }
--- stream_server_config
    proxy_pass unix:$TEST_NGINX_HTML_DIR/nginx.sock;
--- error_log
"proxy_ssl_certificate_by_lua_block" directive is not allowed here
--- no_error_log
[error]
[alert]
--- must_die



=== TEST 3: simple logging
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        ngx.log(ngx.INFO, "proxy_ssl_certificate_by_lua is running!")
    }
--- stream_response
it works!
--- error_log
proxy_ssl_certificate_by_lua is running!
proxy_ssl_certificate_by_lua: handler return value: 0, cert cb exit code: 1
--- no_error_log
[error]
[alert]



=== TEST 4: sleep
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local begin = ngx.now()
        ngx.sleep(0.1)
        print("elapsed in proxy ssl certificate by lua: ", ngx.now() - begin)
    }
--- stream_response
it works!
--- error_log eval
qr/elapsed in proxy ssl certificate by lua: 0.(?:09|1\d)\d+ while loading proxy ssl certificate by lua,/,
--- no_error_log
[error]
[alert]



=== TEST 5: timer
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local function f()
            print("my timer run!")
        end
        local ok, err = ngx.timer.at(0, f)
        if not ok then
            ngx.log(ngx.ERR, "failed to create timer: ", err)
            return
        end
    }
--- stream_response
it works!
--- error_log
my timer run!
proxy_ssl_certificate_by_lua: handler return value: 0, cert cb exit code: 1
--- no_error_log
[error]
[alert]



=== TEST 6: ngx.exit(0) - no yield
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        ngx.exit(0)
        ngx.log(ngx.ERR, "should never reached here...")
    }
--- stream_response
it works!
--- error_log
lua exit with code 0
--- no_error_log
should never reached here
[error]
[alert]
[emerg]



=== TEST 7: ngx.exit(ngx.ERROR) - no yield
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;
    proxy_ssl_conf_command        VerifyMode Peer;

    proxy_ssl_certificate_by_lua_block {
        ngx.exit(ngx.ERROR)
        ngx.log(ngx.ERR, "should never reached here...")
    }
--- error_log eval
[
'lua exit with code -1',
'proxy_ssl_certificate_by_lua: handler return value: -1, cert cb exit code: 0',
qr/.*? SSL_do_handshake\(\) failed .*?callback failed/,
]
--- no_error_log
should never reached here
[alert]
[emerg]



=== TEST 8: ngx.exit(0) -  yield
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        ngx.sleep(0.001)
        ngx.exit(0)

        ngx.log(ngx.ERR, "should never reached here...")
    }
--- stream_response
it works!
--- error_log
lua exit with code 0
--- no_error_log
should never reached here
[error]
[alert]
[emerg]



=== TEST 9: ngx.exit(ngx.ERROR) - yield
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;
    proxy_ssl_conf_command      VerifyMode Peer;

    proxy_ssl_certificate_by_lua_block {
        ngx.sleep(0.001)
        ngx.exit(ngx.ERROR)

        ngx.log(ngx.ERR, "should never reached here...")
    }
--- error_log eval
[
'lua exit with code -1',
'proxy_ssl_certificate_by_lua: cert cb exit code: 0',
qr/.*? SSL_do_handshake\(\) failed .*?callback failed/,
]
--- no_error_log
should never reached here
[alert]
[emerg]



=== TEST 10: lua exception - no yield
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;
    proxy_ssl_conf_command      VerifyMode Peer;

    proxy_ssl_certificate_by_lua_block {
        error("bad bad bad")
        ngx.log(ngx.ERR, "should never reached here...")
    }
--- error_log eval
[
'runtime error: proxy_ssl_certificate_by_lua:2: bad bad bad',
'proxy_ssl_certificate_by_lua: handler return value: 500, cert cb exit code: 0',
qr/.*? SSL_do_handshake\(\) failed .*?callback failed/,
]
--- no_error_log
should never reached here
[alert]
[emerg]



=== TEST 11: lua exception - yield
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;
    proxy_ssl_conf_command      VerifyMode Peer;

    proxy_ssl_certificate_by_lua_block {
        ngx.sleep(0.001)
        error("bad bad bad")
        ngx.log(ngx.ERR, "should never reached here...")
    }
--- error_log eval
[
'runtime error: proxy_ssl_certificate_by_lua:3: bad bad bad',
'proxy_ssl_certificate_by_lua: cert cb exit code: 0',
qr/.*? SSL_do_handshake\(\) failed .*?callback failed/,
]
--- no_error_log
should never reached here
[alert]
[emerg]



=== TEST 12: get phase
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        print("get_phase: ", ngx.get_phase())
    }
--- stream_response
it works!
--- error_log
get_phase: proxy_ssl_cert
--- no_error_log
[error]
[alert]



=== TEST 13: simple logging (by_lua_file)
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;
    proxy_ssl_conf_command      VerifyMode Peer;

    proxy_ssl_certificate_by_lua_file html/a.lua;
--- stream_response
it works!
--- user_files
>>> a.lua
print("proxy ssl certificate by lua is running!")

--- error_log
a.lua:1: proxy ssl certificate by lua is running!
--- no_error_log
[error]
[alert]



=== TEST 14: coroutine API
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local cc, cr, cy = coroutine.create, coroutine.resume, coroutine.yield

        local function f()
            local cnt = 0
            for i = 1, 20 do
                print("co yield: ", cnt)
                cy()
                cnt = cnt + 1
            end
        end

        local c = cc(f)
        for i = 1, 3 do
            print("co resume, status: ", coroutine.status(c))
            cr(c)
        end
    }
--- stream_response
it works!
--- grep_error_log eval: qr/co (?:yield: \d+|resume, status: \w+)/
--- grep_error_log_out
co resume, status: suspended
co yield: 0
co resume, status: suspended
co yield: 1
co resume, status: suspended
co yield: 2
--- no_error_log
[error]
[alert]



=== TEST 15: simple user thread wait with yielding
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local function f()
            ngx.sleep(0.01)
            print("uthread: hello in thread")
            return "done"
        end

        local t, err = ngx.thread.spawn(f)
        if not t then
            ngx.log(ngx.ERR, "uthread: failed to spawn thread: ", err)
            return ngx.exit(ngx.ERROR)
        end

        print("uthread: thread created: ", coroutine.status(t))

        local ok, res = ngx.thread.wait(t)
        if not ok then
            print("uthread: failed to wait thread: ", res)
            return
        end

        print("uthread: ", res)
    }
--- stream_response
it works!
--- no_error_log
[error]
[alert]
--- grep_error_log eval: qr/uthread: [^.,]+/
--- grep_error_log_out
uthread: thread created: running while loading proxy ssl certificate by lua
uthread: hello in thread while loading proxy ssl certificate by lua
uthread: done while loading proxy ssl certificate by lua



=== TEST 16: uthread (kill)
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local function f()
            ngx.log(ngx.INFO, "uthread: hello from f()")
            ngx.sleep(1)
        end

        local t, err = ngx.thread.spawn(f)
        if not t then
            ngx.log(ngx.ERR, "failed to spawn thread: ", err)
            return ngx.exit(ngx.ERROR)
        end

        local ok, res = ngx.thread.kill(t)
        if not ok then
            ngx.log(ngx.ERR, "failed to kill thread: ", res)
            return
        end

        ngx.log(ngx.INFO, "uthread: killed")

        local ok, err = ngx.thread.kill(t)
        if not ok then
            ngx.log(ngx.INFO, "uthread: failed to kill: ", err)
        end
    }
--- stream_response
it works!
--- no_error_log
[error]
[alert]
[emerg]
--- grep_error_log eval: qr/uthread: [^.,]+/
--- grep_error_log_out
uthread: hello from f() while loading proxy ssl certificate by lua
uthread: killed while loading proxy ssl certificate by lua
uthread: failed to kill: already waited or killed while loading proxy ssl certificate by lua



=== TEST 17: ngx.exit(ngx.OK) - no yield
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        ngx.exit(ngx.OK)
        ngx.log(ngx.ERR, "should never reached here...")
    }
--- stream_response
it works!
--- error_log eval
[
'proxy_ssl_certificate_by_lua: handler return value: 0, cert cb exit code: 1',
qr/\[debug\] .*? SSL_do_handshake: 1/,
'lua exit with code 0',
]
--- no_error_log
should never reached here
[alert]
[emerg]



=== TEST 18: proxy_ssl_certificate_by_lua* without yield API (simple logic)
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        print("proxy ssl certificate: simple test start")

        -- Simple calculations without yield
        local sum = 0
        for i = 1, 10 do
            sum = sum + i
        end

        print("proxy ssl certificate: calculated sum: ", sum)

        -- String operations
        local str = "hello"
        str = str .. " world"
        print("proxy ssl certificate: concatenated string: ", str)

        -- Table operations
        local t = {a = 1, b = 2, c = 3}
        local count = 0
        for k, v in pairs(t) do
            count = count + v
        end
        print("proxy ssl certificate: table sum: ", count)

        print("proxy ssl certificate: simple test done")
    }
--- stream_response
it works!
--- grep_error_log eval: qr/(proxy ssl certificate: simple test start|proxy ssl certificate: calculated sum: 55|proxy ssl certificate: concatenated string: hello world|proxy ssl certificate: table sum: 6|proxy ssl certificate: simple test done)/
--- grep_error_log_out
proxy ssl certificate: simple test start
proxy ssl certificate: calculated sum: 55
proxy ssl certificate: concatenated string: hello world
proxy ssl certificate: table sum: 6
proxy ssl certificate: simple test done

--- no_error_log
[error]
[alert]
[emerg]



=== TEST 19: ngx.ctx to pass data from downstream phase to upstream phase
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    preread_by_lua_block {
        ngx.ctx.greeting = "I am from preread phase"
    }

    proxy_ssl_certificate_by_lua_block {
        ngx.log(ngx.INFO, "greeting: ", ngx.ctx.greeting)
    }
--- stream_response
it works!
--- error_log
greeting: I am from preread phase
proxy_ssl_certificate_by_lua: handler return value: 0, cert cb exit code: 1
--- no_error_log
[error]
[alert]



=== TEST 20: upstream connection aborted
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;
    proxy_connect_timeout         100ms;

    proxy_ssl_certificate_by_lua_block {
        ngx.sleep(0.2)
    }
--- error_log
proxy_ssl_certificate_by_lua: cert cb aborted
--- no_error_log
[error]
[alert]
--- wait: 0.5



=== TEST 21: cosocket
--- stream_config
    server {
        listen 127.0.0.1:$TEST_NGINX_RAND_PORT_1;

        return "it works!\n";
    }

    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        do
            local sock = ngx.socket.tcp()
            sock:settimeout(2000)

            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_RAND_PORT_1)
            if not ok then
                ngx.log(ngx.ERR, "failed to connect: ", err)
                return
            end

            ngx.log(ngx.INFO, "connected: ", ok)

            while true do
                local line, err = sock:receive()
                if not line then
                    -- ngx.log(ngx.ERR, "failed to receive response status line: ", err)
                    break
                end
                ngx.log(ngx.INFO, "received: ", line)
            end

            local ok, err = sock:close()
            ngx.log(ngx.INFO, "close: ", ok, " ", err)
        end -- do
        -- collectgarbage()
    }
--- stream_response
it works!
--- error_log
connected: 1
received: it works!
close: 1 nil
--- no_error_log
[error]
[alert]



=== TEST 22: TLSv1.2, without proxy_ssl_certificate, lua does not set cert
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_protocols TLSv1.2;
        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_protocols           TLSv1.2;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local proxy_ssl = require "ngx.proxyssl"

        local ver, err = proxy_ssl.get_tls1_version_str()
        if not ver then
            ngx.log(ngx.ERR, "failed to get TLS1 version: ", err)
            return
        end
        ngx.log(ngx.INFO, "got TLS1 version: ", ver)
    }
--- stream_response
--- error_log
got TLS1 version: TLSv1.2
client sent no required SSL certificate
--- no_error_log
[error]
[alert]



=== TEST 23: TLSv1.2, without proxy_ssl_certificate, lua sets cert
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_protocols TLSv1.2;
        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_protocols           TLSv1.2;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local ssl = require "ngx.ssl"
        local proxy_ssl = require "ngx.proxyssl"
        local proxy_ssl_cert = require "ngx.ssl.proxysslcert"

        local ver, err = proxy_ssl.get_tls1_version_str()
        if not ver then
            ngx.log(ngx.ERR, "failed to get TLS1 version: ", err)
            return
        end
        ngx.log(ngx.INFO, "got TLS1 version: ", ver)

        local f = assert(io.open("t/cert/mtls_client.crt"))
        local cert_data = f:read("*a")
        f:close()

        local cert, err = ssl.parse_pem_cert(cert_data)
        if not cert then
            ngx.log(ngx.ERR, "failed to parse pem cert: ", err)
            return
        end

        local ok, err = proxy_ssl_cert.set_cert(cert)
        if not ok then
            ngx.log(ngx.ERR, "failed to set cert: ", err)
            return
        end

        local f = assert(io.open("t/cert/mtls_client.key"))
        local pkey_data = f:read("*a")
        f:close()

        local pkey, err = ssl.parse_pem_priv_key(pkey_data)
        if not pkey then
            ngx.log(ngx.ERR, "failed to parse pem key: ", err)
            return
        end

        local ok, err = proxy_ssl_cert.set_priv_key(pkey)
        if not ok then
            ngx.log(ngx.ERR, "failed to set private key: ", err)
            return
        end
    }
--- stream_response
it works!
--- error_log
got TLS1 version: TLSv1.2
--- no_error_log
[error]
[alert]



=== TEST 24: TLSv1.3, without proxy_ssl_certificate, lua does not set cert
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_protocols TLSv1.3;
        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_protocols           TLSv1.3;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local proxy_ssl = require "ngx.proxyssl"

        local ver, err = proxy_ssl.get_tls1_version_str()
        if not ver then
            ngx.log(ngx.ERR, "failed to get TLS1 version: ", err)
            return
        end
        ngx.log(ngx.INFO, "got TLS1 version: ", ver)
    }
--- stream_response
--- error_log
got TLS1 version: TLSv1.3
client sent no required SSL certificate
--- no_error_log
[error]
[alert]



=== TEST 25: TLSv1.3, without proxy_ssl_certificate, lua sets cert
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_protocols TLSv1.3;
        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_protocols           TLSv1.3;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local ssl = require "ngx.ssl"
        local proxy_ssl = require "ngx.proxyssl"
        local proxy_ssl_cert = require "ngx.ssl.proxysslcert"

        local ver, err = proxy_ssl.get_tls1_version_str()
        if not ver then
            ngx.log(ngx.ERR, "failed to get TLS1 version: ", err)
            return
        end
        ngx.log(ngx.INFO, "got TLS1 version: ", ver)

        local f = assert(io.open("t/cert/mtls_client.crt"))
        local cert_data = f:read("*a")
        f:close()

        local cert, err = ssl.parse_pem_cert(cert_data)
        if not cert then
            ngx.log(ngx.ERR, "failed to parse pem cert: ", err)
            return
        end

        local ok, err = proxy_ssl_cert.set_cert(cert)
        if not ok then
            ngx.log(ngx.ERR, "failed to set cert: ", err)
            return
        end

        local f = assert(io.open("t/cert/mtls_client.key"))
        local pkey_data = f:read("*a")
        f:close()

        local pkey, err = ssl.parse_pem_priv_key(pkey_data)
        if not pkey then
            ngx.log(ngx.ERR, "failed to parse pem key: ", err)
            return
        end

        local ok, err = proxy_ssl_cert.set_priv_key(pkey)
        if not ok then
            ngx.log(ngx.ERR, "failed to set private key: ", err)
            return
        end
    }
--- stream_response
it works!
--- error_log
got TLS1 version: TLSv1.3
--- no_error_log
[error]
[alert]



=== TEST 26: TLSv1.2, with proxy_ssl_certificate, lua does not set cert
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_protocols TLSv1.2;
        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_protocols           TLSv1.2;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local proxy_ssl = require "ngx.proxyssl"

        local ver, err = proxy_ssl.get_tls1_version_str()
        if not ver then
            ngx.log(ngx.ERR, "failed to get TLS1 version: ", err)
            return
        end
        ngx.log(ngx.INFO, "got TLS1 version: ", ver)
    }
--- stream_response
it works!
--- error_log
got TLS1 version: TLSv1.2
--- no_error_log
[error]
[alert]



=== TEST 27: TLSv1.3, with proxy_ssl_certificate, lua does not set cert
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_protocols TLSv1.3;
        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_protocols           TLSv1.3;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local proxy_ssl = require "ngx.proxyssl"

        local ver, err = proxy_ssl.get_tls1_version_str()
        if not ver then
            ngx.log(ngx.ERR, "failed to get TLS1 version: ", err)
            return
        end
        ngx.log(ngx.INFO, "got TLS1 version: ", ver)
    }
--- stream_response
it works!
--- error_log
got TLS1 version: TLSv1.3
--- no_error_log
[error]
[alert]



=== TEST 28: proxy_ssl_certificate_by_lua takes precedence over proxy_ssl_certificate
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_protocols TLSv1.3;
        ssl_verify_client on;
        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;
        ssl_client_certificate ../../cert/mtls_ca.crt;

        return 'it works!\n';
    }
--- stream_server_config
    proxy_pass                    unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                     on;
    proxy_ssl_protocols           TLSv1.3;
    proxy_ssl_verify              on;
    proxy_ssl_name                example.com;
    proxy_ssl_certificate         ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key     ../../cert/mtls_client.key;
    proxy_ssl_trusted_certificate ../../cert/mtls_ca.crt;
    proxy_ssl_session_reuse       off;

    proxy_ssl_certificate_by_lua_block {
        local ssl = require "ngx.ssl"
        local proxy_ssl = require "ngx.proxyssl"
        local proxy_ssl_cert = require "ngx.ssl.proxysslcert"

        local ver, err = proxy_ssl.get_tls1_version_str()
        if not ver then
            ngx.log(ngx.ERR, "failed to get TLS1 version: ", err)
            return
        end
        ngx.log(ngx.INFO, "got TLS1 version: ", ver)

        -- there exists proxy_ssl_certificate and proxy_ssl_certificate_key
        -- directives in nginx conf, but here we use lua codes to clear them,
        -- so that it can prove that proxy_ssl_certificate_by_lua takes
        -- precedence over proxy_ssl_certificate related directives
        proxy_ssl_cert.clear_certs()
    }
--- stream_response
--- error_log
got TLS1 version: TLSv1.3
client sent no required SSL certificate
--- no_error_log
[error]
[alert]
