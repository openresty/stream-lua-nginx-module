# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3);

#no_diff();
#no_long_string();
run_tests();

__DATA__

=== TEST 1: basic print
--- stream_server_config
    content_by_lua_block {
        local ok, err = ngx.print("Hello, Lua!\n")
        if not ok then
            ngx.log(ngx.ERR, "print failed: ", err)
        end
    }
--- stream_response
Hello, Lua!
--- no_error_log
[error]



=== TEST 2: basic say
--- stream_server_config
    content_by_lua_block {
        local ok, err = ngx.say("Hello, Lua!")
        if not ok then
            ngx.log(ngx.ERR, "say failed: ", err)
            return
        end
        local ok, err = ngx.say("Yay! ", 123)
        if not ok then
            ngx.log(ngx.ERR, "say failed: ", err)
            return
        end
    }
--- stream_response
Hello, Lua!
Yay! 123
--- no_error_log
[error]



=== TEST 3: no ngx.echo
--- stream_server_config
    content_by_lua_block { ngx.echo("Hello, Lua!\n") }
--- stream_response
--- error_log eval
qr/content_by_lua\(nginx\.conf:\d+\):1: attempt to call field 'echo' \(a nil value\)/



=== TEST 4: calc expression
--- stream_server_config
    content_by_lua_file html/calc.lua;
--- user_files
>>> calc.lua
local function uri_unescape(uri)
    local function convert(hex)
        return string.char(tonumber("0x"..hex))
    end
    local s = string.gsub(uri, "%%([0-9a-fA-F][0-9a-fA-F])", convert)
    return s
end

local function eval_exp(str)
    return loadstring("return "..str)()
end

local exp_str = 1+2*math.sin(3)/math.exp(4)-math.sqrt(2)
-- print("exp: '", exp_str, "'\n")
local status, res
status, res = pcall(uri_unescape, exp_str)
if not status then
    ngx.print("error: ", res, "\n")
    return
end
status, res = pcall(eval_exp, res)
if status then
    ngx.print("result: ", res, "\n")
else
    ngx.print("error: ", res, "\n")
end

--- stream_response
result: -0.4090441561579
--- no_error_log
[error]



=== TEST 5: nil is "nil"
--- stream_server_config
    content_by_lua_block { ngx.say(nil) }
--- stream_response
nil
--- no_error_log
[error]



=== TEST 6: write boolean
--- stream_server_config
    content_by_lua_block { ngx.say(true, " ", false) }
--- stream_response
true false
--- no_error_log
[error]



=== TEST 7: nginx quote sql string 1
--- stream_server_config
   content_by_lua_block { ngx.say(ngx.quote_sql_str('hello\n\r\'"\\')) }
--- stream_response
'hello\n\r\'\"\\'
--- no_error_log
[error]



=== TEST 8: nginx quote sql string 2
--- stream_server_config
    content_by_lua_block { ngx.say(ngx.quote_sql_str("hello\n\r'\"\\")) }
--- stream_response
'hello\n\r\'\"\\'
--- no_error_log
[error]
--- LAST



=== TEST 9: multiple eof
--- config
    location /lua {
        content_by_lua '
            ngx.say("Hi")

            local ok, err = ngx.eof()
            if not ok then
                ngx.log(ngx.WARN, "eof failed: ", err)
                return
            end

            ok, err = ngx.eof()
            if not ok then
                ngx.log(ngx.WARN, "eof failed: ", err)
                return
            end

        ';
    }
--- request
GET /lua
--- response_body
Hi
--- no_error_log
[error]
--- error_log
eof failed: seen eof



=== TEST 10: nginx vars in script path
--- config
    location ~ ^/lua/(.+)$ {
        content_by_lua_file html/$1.lua;
    }
--- user_files
>>> calc.lua
local a,b = ngx.var.arg_a, ngx.var.arg_b
ngx.say(a+b)
--- request
GET /lua/calc?a=19&b=81
--- response_body
100



=== TEST 11: nginx vars in script path
--- config
    location ~ ^/lua/(.+)$ {
        content_by_lua_file html/$1.lua;
    }
    location /main {
        echo_location /lua/sum a=3&b=2;
        echo_location /lua/diff a=3&b=2;
    }
--- user_files
>>> sum.lua
local a,b = ngx.var.arg_a, ngx.var.arg_b
ngx.say(a+b)
>>> diff.lua
local a,b = ngx.var.arg_a, ngx.var.arg_b
ngx.say(a-b)
--- request
GET /main
--- response_body
5
1



=== TEST 12: basic print (HEAD + HTTP 1.1)
--- config
    location /lua {
        # NOTE: the newline escape sequence must be double-escaped, as nginx config
        # parser will unescape first!
        content_by_lua 'ngx.print("Hello, Lua!\\n")';
    }
--- request
HEAD /lua
--- response_body



=== TEST 13: basic print (HEAD + HTTP 1.0)
--- config
    location /lua {
        # NOTE: the newline escape sequence must be double-escaped, as nginx config
        # parser will unescape first!
        content_by_lua '
            ngx.print("Hello, Lua!\\n")
        ';
    }
--- request
HEAD /lua HTTP/1.0
--- response_headers
!Content-Length
--- response_body



=== TEST 14: headers_sent & HEAD
--- config
    location /lua {
        content_by_lua '
            ngx.say(ngx.headers_sent)
            local ok, err = ngx.flush()
            if not ok then
                ngx.log(ngx.WARN, "failed to flush: ", err)
                return
            end
            ngx.say(ngx.headers_sent)
        ';
    }
--- request
HEAD /lua
--- response_body
--- no_error_log
[error]
--- error_log
failed to flush: header only



=== TEST 15: HEAD & ngx.say
--- config
    location /lua {
        content_by_lua '
            ngx.send_headers()
            local ok, err = ngx.say(ngx.headers_sent)
            if not ok then
                ngx.log(ngx.WARN, "failed to say: ", err)
                return
            end
        ';
    }
--- request
HEAD /lua
--- response_body
--- no_error_log
[error]
--- error_log
failed to say: header only



=== TEST 16: ngx.eof before ngx.say
--- config
    location /lua {
        content_by_lua '
            local ok, err = ngx.eof()
            if not ok then
                ngx.log(ngx.ERR, "eof failed: ", err)
                return
            end

            ok, err = ngx.say(ngx.headers_sent)
            if not ok then
                ngx.log(ngx.WARN, "failed to say: ", err)
                return
            end
        ';
    }
--- request
GET /lua
--- response_body
--- no_error_log
[error]
--- error_log
failed to say: seen eof



=== TEST 17: headers_sent + GET
--- config
    location /lua {
        content_by_lua '
            -- print("headers sent: ", ngx.headers_sent)
            ngx.say(ngx.headers_sent)
            ngx.say(ngx.headers_sent)
            -- ngx.flush()
            ngx.say(ngx.headers_sent)
        ';
    }
--- request
GET /lua
--- response_body
false
true
true



=== TEST 18: HTTP 1.0 response with Content-Length
--- config
    location /lua {
        content_by_lua '
            data = "hello,\\nworld\\n"
            ngx.header["Content-Length"] = #data
            ngx.say("hello,")
            ngx.flush()
            -- ngx.location.capture("/sleep")
            ngx.say("world")
        ';
    }
    location /sleep {
        echo_sleep 2;
    }
    location /main {
        proxy_pass http://127.0.0.1:$server_port/lua;
    }
--- request
GET /main
--- response_headers
Content-Length: 13
--- response_body
hello,
world
--- timeout: 5



=== TEST 19: ngx.print table arguments (github issue #54)
--- config
    location /t {
        content_by_lua 'ngx.print({10, {0, 5}, 15}, 32)';
    }
--- request
    GET /t
--- response_body chop
10051532



=== TEST 20: ngx.say table arguments (github issue #54)
--- config
    location /t {
        content_by_lua 'ngx.say({10, {0, "5"}, 15}, 32)';
    }
--- request
    GET /t
--- response_body
10051532



=== TEST 21: Lua file does not exist
--- config
    location /lua {
        content_by_lua_file html/test2.lua;
    }
--- user_files
>>> test.lua
v = ngx.var["request_uri"]
ngx.print("request_uri: ", v, "\n")
--- request
GET /lua?a=1&b=2
--- response_body_like: 404 Not Found
--- error_code: 404
--- error_log eval
qr/failed to load external Lua file ".*?test2\.lua": cannot open .*? No such file or directory/



=== TEST 22: .lua file with shebang
--- config
    location /lua {
        content_by_lua_file html/test.lua;
    }
--- user_files
>>> test.lua
#!/bin/lua

ngx.say("line ", debug.getinfo(1).currentline)
--- request
GET /lua?a=1&b=2
--- response_body
line 3
--- no_error_log
[error]



=== TEST 23: syntax error in inlined Lua code
--- config
    location /lua {
        content_by_lua 'for end';
    }
--- request
GET /lua
--- response_body_like: 500 Internal Server Error
--- error_code: 500
--- error_log eval
qr/failed to load inlined Lua code: /

