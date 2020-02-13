# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

plan tests => repeat_each() * 20;

our $HtmlDir = html_dir;

#$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
#$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();
#no_shuffle();
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



=== TEST 3: receiveany with limited, max <= 0
--- stream_server_config
    content_by_lua_block {
        local sock, err = ngx.req.socket(true)
        if sock == nil then
            ngx.log(ngx.ERR, 'raw req socket error: ', err)
            return
        end
        sock:settimeouts(500, 500, 500)

        local function receiveany_log_err(...)
            local ok, err = pcall(sock.receiveany, sock, ...)
            if not ok then
                ngx.log(ngx.ERR, 'failed receiveany ', err)
            end
        end


        receiveany_log_err(0)
        receiveany_log_err(-1)
        receiveany_log_err(100, 200)
        receiveany_log_err()
        receiveany_log_err(nil)
    }
--- error_log
bad argument #2 to '?' (bad max argument)
bad argument #2 to '?' (bad max argument)
expecting 2 arguments (including the object), but got 3
expecting 2 arguments (including the object), but got 1
bad argument #2 to '?' (bad max argument)



=== TEST 4: receiveany send data after read side timeout
--- stream_server_config
    content_by_lua_block {
        local sock, err = ngx.req.socket(true)
        if sock == nil then
            ngx.log(ngx.ERR, 'failed to get raw req socket', err)
            return
        end
        sock:settimeouts(500, 500, 500)

        local data, err, bytes = nil, nil
        while true do
            data, err = sock:receiveany(1024)
            if err then
                if err ~= 'closed' then
                    ngx.log(ngx.ERR, 'receiveany unexpected err: ', err)
                    break
                end

                data = "send data after read side closed"
                bytes, err = sock:send(data)
                if not bytes then
                    ngx.log(ngx.ERR, 'failed to send after error ',err)
                end

                break
            end
            ngx.say(data)
        end

        sock:send("send data after read side ")
        sock:send(err)
    }
--- stream_response chomp
send data after read side timeout
--- error_log
receiveany unexpected err: timeout

