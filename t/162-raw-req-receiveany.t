# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket "no_plan";
use Test::Nginx::Socket::Lua::Stream;

#repeat_each(2);

#plan tests => repeat_each() * 49;

our $HtmlDir = html_dir;

#$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
#$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();
no_shuffle();
run_tests();

__DATA__

=== TEST 1: sanity
--- stream_server_config

    content_by_lua_block {
        local sock, err = ngx.req.socket(true)
        if not sock then
            ngx.log(ngx.ERR, "server: failed to get raw req socket: ", err)
            return
        end
        ngx.log(ngx.INFO, "Got raw req socket")
        local data, err = sock:receiveany(500)
        if not data then
            ngx.log(ngx.ERR, "server: failed to receive: ", err)
            return
        end
        ngx.log(ngx.INFO, "Got: ", #data, " bytes")

        local bytes, err = sock:send("1: received: " .. data .. "\n")
        if not bytes then
            ngx.log(ngx.ERR, "server: failed to send: ", err)
            return
        end
    }

--- stream_request: hello
--- stream_response
1: received: hello
--- no_error_log
stream lua socket tcp_nodelay
[error]
--- error_log
Got raw req socket
Got: 5 bytes



=== TEST 2: receiveany small block size for a big size block
--- stream_server_config
    content_by_lua_block {
        local sock, err = ngx.req.socket(true)
        if not sock then
            ngx.log(ngx.ERR, "server: failed to get raw req socket: ", err)
            return
        end
        sock:settimeouts(500, 100, 500)
        ngx.sleep(0.2)
        ngx.log(ngx.INFO, 'receiveany every 3 bytes per read ...')
        local i = 0
        while true do
            i = i + 1
            ngx.log(ngx.INFO, 'reading: ', i)
            local data, err = sock:receiveany(3)
            if not data then
                if err == 'closed' then
                    ngx.log(ngx.INFO, 'client closed')
                    break
                end
                if err == 'timeout' then
                    ngx.log(ngx.INFO, 'client timeout, considered as closed')
                    break
                end
                ngx.log(ngx.ERR, 'server receiveany error: ', err)
                break
            end
            if i == 1 then
                ngx.log(ngx.INFO, 'send back ok ...')
                local ok, err = sock:send("ok\n")
                if not ok then
                    ngx.log(ngx.ERR, "failed to send: ", err)
                    return
                end
            end
            ngx.log(ngx.INFO, "Time ", i, " - got ", #data, " bytes: ", data)
            sock:send("receive: " .. data .. "\n")
        end
    }

--- stream_request: hello, stream receiveany!
--- stream_response
ok
receive: hel
receive: lo,
receive:  st
receive: rea
receive: m r
receive: ece
receive: ive
receive: any
receive: !
--- no_error_log
receiveany error: 
--- error_log
read timed out
client timeout
