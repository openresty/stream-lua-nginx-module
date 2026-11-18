# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);

#master_on();
#workers(1);
#log_level('debug');
#log_level('warn');
#worker_connections(1024);

plan tests => repeat_each() * (blocks() * 2);

no_long_string();
#no_shuffle();

run_tests();

__DATA__

=== TEST 1: throw 500
--- stream_server_config
    access_by_lua_block { ngx.exit(500) }
    content_by_lua_block { ngx.exit(ngx.OK) }
--- error_log
finalize stream request: 500



=== TEST 2: throw 0
--- stream_server_config
    access_by_lua_block { ngx.say('Hi'); ngx.eof(); ngx.exit(0) }
    content_by_lua_block { ngx.exit(ngx.OK) }
--- stream_response
Hi



=== TEST 3: sync output + exit 200 in access_by_lua
--- stream_server_config
    access_by_lua_block {
        ngx.say("sync output")
        ngx.exit(200)
    }
    content_by_lua_block { ngx.say("should not appear") }
--- stream_response
sync output

--- timeout: 5



=== TEST 4: sleep + say then exit 0 without trailing sleep
--- stream_server_config
    access_by_lua_block {
        ngx.sleep(0.001)
        ngx.say("done")
        ngx.eof()
        ngx.exit(0)
    }
    content_by_lua_block { ngx.say("should not appear") }
--- stream_response
done

--- timeout: 5
