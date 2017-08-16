# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * 3;

#no_diff();
no_long_string();
#master_on();
#workers(2);

run_tests();

__DATA__

=== TEST 1: __ngx_req and __ngx_cycle
--- stream_config
    init_by_lua_block {
        my_cycle = __ngx_cycle
    }

--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"
        local function tonum(ud)
            return tonumber(ffi.cast("uintptr_t", ud))
        end
        ngx.say(string.format("init: cycle=%#x", tonum(my_cycle)))
        ngx.say(string.format("content cycle=%#x", tonum(__ngx_cycle)))
        ngx.say(string.format("content req=%#x", tonum(__ngx_req)))
    }
--- stream_response_like chop
^init: cycle=(0x[a-f0-9]{4,})
content cycle=\1
content req=0x[a-f0-9]{4,}
$
--- no_error_log
[error]
