# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
use Cwd qw(abs_path realpath);
use File::Basename;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 2);

my $NginxBinary = $ENV{'TEST_NGINX_BINARY'} || 'nginx';
my $openssl_version = eval { `$NginxBinary -V 2>&1` };

if ($openssl_version =~ m/\bBoringSSL\b/) {
    $ENV{TEST_NGINX_BORINGSSL} = 1;
}

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_MEMCACHED_PORT} ||= 11211;
$ENV{TEST_NGINX_RESOLVER} ||= '8.8.8.8';
$ENV{TEST_NGINX_SERVER_SSL_PORT} ||= 12345;
$ENV{TEST_NGINX_CERT_DIR} ||= dirname(realpath(abs_path(__FILE__)));

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();

sub read_file {
    my $infile = shift;
    open my $in, $infile
        or die "cannot open $infile for reading: $!";
    my $cert = do { local $/; <$in> };
    close $in;
    $cert;
}

our $DSTRootCertificate = read_file("t/cert/root-ca.crt");
our $GoogleRootCertificate = read_file("t/cert/google.crt");
our $TestCertificate = read_file("t/cert/test.crt");
our $TestCertificateKey = read_file("t/cert/test.key");
our $TestCRL = read_file("t/cert/test.crl");

run_tests();

__DATA__

=== TEST 1: www.google.com
--- stream_server_config
    resolver $TEST_NGINX_RESOLVER ipv6=off;
    content_by_lua_block {
            do
                local sock = ngx.socket.tcp()
                sock:settimeout(2000)
                local ok, err = sock:connect("www.google.com", 443)
                if not ok then
                    ngx.say("failed to connect: ", err)
                    return
                end

                ngx.say("connected: ", ok)

                local sess, err = sock:sslhandshake()
                if not sess then
                    ngx.say("failed to do SSL handshake: ", err)
                    return
                end

                ngx.say("ssl handshake: ", type(sess))

                local req = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
                local bytes, err = sock:send(req)
                if not bytes then
                    ngx.say("failed to send http request: ", err)
                    return
                end

                ngx.say("sent http request: ", bytes, " bytes.")

                local line, err = sock:receive()
                if not line then
                    ngx.say("failed to receive response status line: ", err)
                    return
                end

                ngx.say("received: ", line)

                local session, err = sock:getsslsession()
                ngx.say("ssl session: ", type(session))

                local ok, err = sock:close()
                ngx.say("close: ", ok, " ", err)
            end  -- do
            collectgarbage()
    }
--- config
    server_tokens off;
--- stream_response_like chop
\Aconnected: 1
ssl handshake: userdata
sent http request: 59 bytes.
received: HTTP/1.1 (?:200 OK|302 Found)
ssl session: userdata
close: 1 nil
\z
--- timeout: 5



=== TEST 2: no SNI, no verify
--- stream_config
    server {
        listen $TEST_NGINX_SERVER_SSL_PORT ssl;
        ssl_certificate ../html/test.crt;
        ssl_certificate_key ../html/test.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            local data = sock:receive()
            if data == "ping" then
                ngx.say("pong")
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        local ssl_session
        local function http_req()
            local ffi = require "ffi"
            local sock = ngx.socket.tcp()
            sock:settimeout(2000)
            local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_SSL_PORT)
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            ssl_session, err = sock:sslhandshake(ssl_session)
            if not ssl_session then
                ngx.say("failed to do SSL handshake: ", err)
                return
            end

            ngx.say("ssl handshake: ", type(ssl_session))

            local req = "ping"
            local bytes, err = sock:send(req .. '\n')
            if not bytes then
                ngx.say("failed to send request: ", err)
                return
            end

            ngx.say("sent: ", req)

            local line, err = sock:receive()
            if not line then
                ngx.say("failed to receive response: ", err)
                return
            end

            ngx.say("received: ", line)

            ssl_session, err = sock:getsslsession()
            ngx.say("ssl session: ", type(ssl_session))
            local ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end

        http_req()
        http_req()
    }

--- stream_response eval
qr/connected: 1
ssl handshake: userdata
sent: ping
received: pong
ssl session: userdata
close: 1 nil
connected: 1
ssl handshake: userdata
sent: ping
received: pong
ssl session: userdata
close: 1 nil
/

--- user_files eval
">>> test.key
$::TestCertificateKey
>>> test.crt
$::TestCertificate"
