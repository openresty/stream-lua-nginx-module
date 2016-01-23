# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

#worker_connections(1014);
#master_on();
log_level('debug');

repeat_each(3);

plan tests => repeat_each() * (blocks() * 3);

our $HtmlDir = html_dir;
#warn $html_dir;

$ENV{TEST_NGINX_HTML_DIR} = $HtmlDir;
$ENV{TEST_NGINX_REDIS_PORT} ||= 6379;

#no_diff();
#no_long_string();

$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';

#no_shuffle();
no_long_string();

sub read_file {
    my $infile = shift;
    open my $in, $infile
        or die "cannot open $infile for reading: $!";
    my $cert = do { local $/; <$in> };
    close $in;
    $cert;
}

our $TestCertificate = read_file("t/cert/test.crt");
our $TestCertificateKey = read_file("t/cert/test.key");

run_tests();

__DATA__

=== TEST 1: sanity
--- stream_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua';"
--- stream_server_config
    content_by_lua_block {
        package.loaded.foo = nil;
        local foo = require "foo";
        foo.hi()
    }
--- user_files
>>> foo.lua
module(..., package.seeall);

function foo ()
    return 1
    return 2
end
--- stream_response
--- error_log
error loading module 'foo' from file



=== TEST 2: print lua empty strings
--- stream_server_config
    content_by_lua_block { ngx.print("") ngx.flush() ngx.print("Hi") }
--- stream_response chop
Hi
--- no_error_log
[error]



=== TEST 3: say lua empty strings
--- stream_server_config
    content_by_lua_block { ngx.say("") ngx.flush() ngx.print("Hi") }
--- stream_response eval
"
Hi"
--- no_error_log
[error]



=== TEST 4: unexpected globals sharing by using _G
--- stream_server_config
    content_by_lua_block {
        if _G.t then
            _G.t = _G.t + 1
        else
            _G.t = 0
        end
        ngx.say(t)
    }
--- stream_server_config2
    content_by_lua_block {
        if _G.t then
            _G.t = _G.t + 1
        else
            _G.t = 0
        end
        ngx.say(t)
    }
--- stream_server_config3
    content_by_lua_block {
        if _G.t then
            _G.t = _G.t + 1
        else
            _G.t = 0
        end
        ngx.say(t)
    }

--- stream_response
0
0
0
--- no_error_log
[error]



=== TEST 5: lua_code_cache off + setkeepalive
--- stream_config eval
    "lua_package_path '$::HtmlDir/?.lua;./?.lua';"
--- stream_server_config
    lua_code_cache off;
    content_by_lua_block {
        local test = require "test"
        local port = $TEST_NGINX_REDIS_PORT
        test.go(port)
    }
--- user_files
>>> test.lua
module("test", package.seeall)

function go(port)
    local sock = ngx.socket.tcp()
    local sock2 = ngx.socket.tcp()

    sock:settimeout(1000)
    sock2:settimeout(6000000)

    local ok, err = sock:connect("127.0.0.1", port)
    if not ok then
        ngx.say("failed to connect: ", err)
        return
    end

    local ok, err = sock2:connect("127.0.0.1", port)
    if not ok then
        ngx.say("failed to connect: ", err)
        return
    end

    local ok, err = sock:setkeepalive(100, 100)
    if not ok then
        ngx.say("failed to set reusable: ", err)
    end

    local ok, err = sock2:setkeepalive(200, 100)
    if not ok then
        ngx.say("failed to set reusable: ", err)
    end

    ngx.say("done")
end
--- stap2
F(ngx_close_connection) {
    println("=== close connection")
    print_ubacktrace()
}
--- stap_out2
--- stream_response
done
--- wait: 0.5
--- no_error_log
[error]



=== TEST 6: .lua file of exactly N*1024 bytes (github issue #385)
--- stream_server_config
    content_by_lua_file html/a.lua;

--- user_files eval
my $s = "ngx.say('ok')\n";
">>> a.lua\n" . (" " x (8192 - length($s))) . $s;

--- stream_response
ok
--- no_error_log
[error]
