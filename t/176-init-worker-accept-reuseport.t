# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

plan(skip_all => "TEST_NGINX_REUSE_PORT=1 is required "
     . "(TEST_NGINX_REUSE_PORT=1 prove t/176-init-worker-accept-reuseport.t)")
    unless $ENV{TEST_NGINX_REUSE_PORT};

master_on();
repeat_each(1);
workers(2);

plan tests => repeat_each() * (blocks() * 3 + 1);

no_long_string();

our $cpu_clock = <<'_EOC_';
        local ffi = require("ffi")
        ffi.cdef[[
            typedef long time_t;
            typedef struct timeval { time_t tv_sec; time_t tv_usec; } timeval;
            typedef struct {
                struct timeval ru_utime;
                struct timeval ru_stime;
                long pad[14];
            } rusage_t;
            int getrusage(int who, rusage_t *usage);
        ]]
        local ru = ffi.new("rusage_t")
        function cpu_us()
            ffi.C.getrusage(0, ru)   -- 0 = RUSAGE_SELF
            return tonumber(ru.ru_utime.tv_sec) * 1000000
                 + tonumber(ru.ru_utime.tv_usec)
                 + tonumber(ru.ru_stime.tv_sec) * 1000000
                 + tonumber(ru.ru_stime.tv_usec)
        end
_EOC_

run_tests();

__DATA__

=== TEST 1: reuseport re-arm branch (2 workers, pump stays idle)
--- stream_config eval
qq{
    init_by_lua_block {
$main::cpu_clock
    }
    init_worker_by_lua_block {
        local c0 = cpu_us()
        ngx.sleep(1)
        local c1 = cpu_us()
        iw_cpu_us = c1 - c0
    }
}
--- steam_listen_option: reuseport
--- stream_server_config
    content_by_lua_block {
        ngx.say("response ok")
        ngx.say(iw_cpu_us and iw_cpu_us < 50000
                and "cpu idle OK" or "cpu busy: " .. (iw_cpu_us or "?"))
    }
--- stream_response
response ok
cpu idle OK
--- timeout: 15
--- no_error_log
[error]
exited on signal
