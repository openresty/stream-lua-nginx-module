# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream;

worker_connections(1014);
#master_on();
#workers(4);
#log_level('warn');
no_root_location();

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

our $HtmlDir = html_dir;

#$ENV{LUA_CPATH} = "/usr/local/openresty/lualib/?.so;" . $ENV{LUA_CPATH};

no_long_string();
run_tests();

__DATA__

=== TEST 1: pcall works
--- stream_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- stream_server_config
    content_by_lua_block {
        function f(a, b)
            if a == 0 and b == 0 then
                error("zero error")
            end

            return 23, "hello", true
        end

        local res = {pcall(f, 0, 0)}
        ngx.say("res len: ", #res)
        ngx.say("res: ", unpack(res))

        res = {pcall(f, 0)}
        ngx.say("res len: ", #res)
        ngx.say("res: ", unpack(res))
    }
--- stream_response eval
qr/^res len: 2
res: falsecontent_by_lua\(nginx\.conf:\d+\):4: zero error
res len: 4
res: true23hellotrue
$/s
--- no_error_log
[error]



=== TEST 2: xpcall works
--- stream_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua;;';"
--- stream_server_config
    content_by_lua_block {
        function f(a, b)
            if a == 0 and b == 0 then
                error("zero error")
            end

            return 23, "hello", true
        end

        function g()
            return f(0, 0)
        end

        function h()
            return f(0)
        end

        function err(...)
            ngx.say("error handler called: ", ...)
            return "this is the new err"
        end

        local res = {xpcall(g, err)}
        ngx.say("res len: ", #res)
        ngx.say("res: ", unpack(res))

        res = {xpcall(h, err)}
        ngx.say("res len: ", #res)
        ngx.say("res: ", unpack(res))
    }
--- stream_response eval
qr/^error handler called: content_by_lua\(nginx\.conf:\d+\):4: zero error
res len: 2
res: falsethis is the new err
res len: 4
res: true23hellotrue
$/

--- no_error_log
[error]
