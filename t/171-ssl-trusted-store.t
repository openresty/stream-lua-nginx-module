# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
use Cwd qw(abs_path realpath);
use File::Basename;

repeat_each(2);

plan tests => repeat_each() * (blocks() * 5);

my $NginxBinary = $ENV{'TEST_NGINX_BINARY'} || 'nginx';
my $openssl_version = eval { `$NginxBinary -V 2>&1` };

if ($openssl_version =~ m/\bBoringSSL\b/) {
    $ENV{TEST_NGINX_BORINGSSL} = 1;
}

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();
$ENV{TEST_NGINX_SERVER_SSL_PORT} ||= 12345;
$ENV{TEST_NGINX_CERT_DIR} ||= dirname(realpath(abs_path(__FILE__)));

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

our $MTLSCA = read_file("t/cert/mtls_ca.crt");
our $MTLSServer = read_file("t/cert/mtls_server.crt");
our $MTLSServerKey = read_file("t/cert/mtls_server.key");
our $UnrelatedCA = read_file("t/cert/test.crt");

run_tests();

__DATA__

=== TEST 1: settrustedstore: handshake succeeds with custom CA store
--- stream_config
    server {
        listen $TEST_NGINX_SERVER_SSL_PORT ssl;
        ssl_certificate ../html/mtls_server.crt;
        ssl_certificate_key ../html/mtls_server.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            local data = sock:receive()
            if data then
                ngx.say("hello")
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"
        ffi.cdef[[
            typedef struct ngx_stream_lua_request_s       ngx_stream_lua_request_t;
            typedef struct ngx_stream_lua_socket_tcp_upstream_s
                    ngx_stream_lua_socket_tcp_upstream_t;
            typedef struct x509_store_st  X509_STORE;
            typedef struct x509_st        X509;
            typedef struct bio_st         BIO;
            typedef struct bio_method_st  BIO_METHOD;

            X509_STORE *X509_STORE_new(void);
            int  X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
            void X509_STORE_free(X509_STORE *v);

            BIO_METHOD *BIO_s_mem(void);
            BIO *BIO_new(BIO_METHOD *type);
            int  BIO_write(BIO *b, const void *buf, int len);
            void BIO_free(BIO *a);
            X509 *PEM_read_bio_X509(BIO *bp, X509 **x, void *cb, void *u);
            void X509_free(X509 *a);

            int ngx_stream_lua_ffi_socket_tcp_settrustedstore(
                ngx_stream_lua_request_t *r,
                ngx_stream_lua_socket_tcp_upstream_t *u,
                void *store, char **errmsg);
        ]]

        local C = ffi.C

        local function load_store_from_pem(pem)
            local bio = C.BIO_new(C.BIO_s_mem())
            if bio == nil then return nil, "BIO_new failed" end
            if C.BIO_write(bio, pem, #pem) <= 0 then
                C.BIO_free(bio)
                return nil, "BIO_write failed"
            end
            local x509 = C.PEM_read_bio_X509(bio, nil, nil, nil)
            C.BIO_free(bio)
            if x509 == nil then return nil, "PEM_read_bio_X509 failed" end
            local store = C.X509_STORE_new()
            if store == nil then
                C.X509_free(x509)
                return nil, "X509_STORE_new failed"
            end
            if C.X509_STORE_add_cert(store, x509) ~= 1 then
                C.X509_free(x509)
                C.X509_STORE_free(store)
                return nil, "X509_STORE_add_cert failed"
            end
            C.X509_free(x509)
            return ffi.gc(store, C.X509_STORE_free)
        end

        local function settrustedstore(sock, store)
            local base = require "resty.core.base"
            local r = base.get_request()
            if not r then return nil, "no request" end

            local u = sock[1]
            if not u then return nil, "socket not connected" end

            local errmsg = ffi.new("char *[1]")
            local rc = C.ngx_stream_lua_ffi_socket_tcp_settrustedstore(
                r, u, store, errmsg)
            if rc ~= 0 then
                return nil, ffi.string(errmsg[0])
            end
            return true
        end

        local f = assert(io.open("t/cert/mtls_ca.crt"))
        local ca_pem = f:read("*a")
        f:close()

        local store, err = load_store_from_pem(ca_pem)
        if not store then
            ngx.say("failed to load store: ", err)
            return
        end

        local sock = ngx.socket.tcp()
        sock:settimeout(2000)
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_SSL_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local ok, err = settrustedstore(sock, store)
        if not ok then
            ngx.say("failed to settrustedstore: ", err)
            return
        end

        local sess, err = sock:sslhandshake(nil, "example.com", true)
        if not sess then
            ngx.say("failed to do SSL handshake: ", err)
            return
        end

        ngx.say("ssl handshake: ", type(sess))

        local bytes, err = sock:send("ping\n")
        if not bytes then
            ngx.say("failed to send: ", err)
            return
        end

        local line, err = sock:receive()
        if not line then
            ngx.say("failed to receive: ", err)
            return
        end

        ngx.say("received: ", line)
        sock:close()
    }

--- user_files eval
">>> mtls_server.key
$::MTLSServerKey
>>> mtls_server.crt
$::MTLSServer
>>> mtls_ca.crt
$::MTLSCA"
--- stream_response
ssl handshake: userdata
received: hello
--- no_error_log
[error]
[alert]
[crit]



=== TEST 2: handshake fails without a trusted store and without lua_ssl_trusted_certificate
--- stream_config
    server {
        listen $TEST_NGINX_SERVER_SSL_PORT ssl;
        ssl_certificate ../html/mtls_server.crt;
        ssl_certificate_key ../html/mtls_server.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            local data = sock:receive()
            if data then
                ngx.say("hello")
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeout(2000)
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_SSL_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local sess, err = sock:sslhandshake(nil, "example.com", true)
        if not sess then
            ngx.say("failed to do SSL handshake: ", err)
            return
        end

        ngx.say("unexpected success")
        sock:close()
    }

--- user_files eval
">>> mtls_server.key
$::MTLSServerKey
>>> mtls_server.crt
$::MTLSServer"
--- stream_response_like
^failed to do SSL handshake: .+
--- error_log
lua ssl certificate verify error
--- no_error_log
[alert]
[crit]



=== TEST 3: handshake fails with a trusted store that has the wrong CA
--- stream_config
    server {
        listen $TEST_NGINX_SERVER_SSL_PORT ssl;
        ssl_certificate ../html/mtls_server.crt;
        ssl_certificate_key ../html/mtls_server.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            local data = sock:receive()
            if data then
                ngx.say("hello")
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"
        ffi.cdef[[
            typedef struct ngx_stream_lua_request_s       ngx_stream_lua_request_t;
            typedef struct ngx_stream_lua_socket_tcp_upstream_s
                    ngx_stream_lua_socket_tcp_upstream_t;
            typedef struct x509_store_st  X509_STORE;
            typedef struct x509_st        X509;
            typedef struct bio_st         BIO;
            typedef struct bio_method_st  BIO_METHOD;

            X509_STORE *X509_STORE_new(void);
            int  X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
            void X509_STORE_free(X509_STORE *v);

            BIO_METHOD *BIO_s_mem(void);
            BIO *BIO_new(BIO_METHOD *type);
            int  BIO_write(BIO *b, const void *buf, int len);
            void BIO_free(BIO *a);
            X509 *PEM_read_bio_X509(BIO *bp, X509 **x, void *cb, void *u);
            void X509_free(X509 *a);

            int ngx_stream_lua_ffi_socket_tcp_settrustedstore(
                ngx_stream_lua_request_t *r,
                ngx_stream_lua_socket_tcp_upstream_t *u,
                void *store, char **errmsg);
        ]]

        local C = ffi.C

        local function load_store_from_pem(pem)
            local bio = C.BIO_new(C.BIO_s_mem())
            if bio == nil then return nil, "BIO_new failed" end
            if C.BIO_write(bio, pem, #pem) <= 0 then
                C.BIO_free(bio)
                return nil, "BIO_write failed"
            end
            local x509 = C.PEM_read_bio_X509(bio, nil, nil, nil)
            C.BIO_free(bio)
            if x509 == nil then return nil, "PEM_read_bio_X509 failed" end
            local store = C.X509_STORE_new()
            if store == nil then
                C.X509_free(x509)
                return nil, "X509_STORE_new failed"
            end
            if C.X509_STORE_add_cert(store, x509) ~= 1 then
                C.X509_free(x509)
                C.X509_STORE_free(store)
                return nil, "X509_STORE_add_cert failed"
            end
            C.X509_free(x509)
            return ffi.gc(store, C.X509_STORE_free)
        end

        local function settrustedstore(sock, store)
            local base = require "resty.core.base"
            local r = base.get_request()
            if not r then return nil, "no request" end

            local u = sock[1]
            if not u then return nil, "socket not connected" end

            local errmsg = ffi.new("char *[1]")
            local rc = C.ngx_stream_lua_ffi_socket_tcp_settrustedstore(
                r, u, store, errmsg)
            if rc ~= 0 then
                return nil, ffi.string(errmsg[0])
            end
            return true
        end

        local f = assert(io.open("t/cert/test.crt"))
        local ca_pem = f:read("*a")
        f:close()

        local store, err = load_store_from_pem(ca_pem)
        if not store then
            ngx.say("failed to load store: ", err)
            return
        end

        local sock = ngx.socket.tcp()
        sock:settimeout(2000)
        local ok, err = sock:connect("127.0.0.1", $TEST_NGINX_SERVER_SSL_PORT)
        if not ok then
            ngx.say("failed to connect: ", err)
            return
        end

        local ok, err = settrustedstore(sock, store)
        if not ok then
            ngx.say("failed to settrustedstore: ", err)
            return
        end

        local sess, err = sock:sslhandshake(nil, "example.com", true)
        if not sess then
            ngx.say("failed to do SSL handshake: ", err)
            return
        end

        ngx.say("unexpected success")
        sock:close()
    }

--- user_files eval
">>> mtls_server.key
$::MTLSServerKey
>>> mtls_server.crt
$::MTLSServer
>>> unrelated_ca.crt
$::UnrelatedCA"
--- stream_response_like
^failed to do SSL handshake: .+
--- error_log
lua ssl certificate verify error
--- no_error_log
[alert]
[crit]



=== TEST 4: settrustedstore returns "closed" after the socket has been closed
--- stream_config
    server {
        listen $TEST_NGINX_SERVER_SSL_PORT ssl;
        ssl_certificate ../html/mtls_server.crt;
        ssl_certificate_key ../html/mtls_server.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            local data = sock:receive()
            if data then
                ngx.say("hello")
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"
        ffi.cdef[[
            typedef struct ngx_stream_lua_request_s       ngx_stream_lua_request_t;
            typedef struct ngx_stream_lua_socket_tcp_upstream_s
                    ngx_stream_lua_socket_tcp_upstream_t;
            typedef struct x509_store_st  X509_STORE;
            typedef struct x509_st        X509;
            typedef struct bio_st         BIO;
            typedef struct bio_method_st  BIO_METHOD;

            X509_STORE *X509_STORE_new(void);
            int  X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
            void X509_STORE_free(X509_STORE *v);

            BIO_METHOD *BIO_s_mem(void);
            BIO *BIO_new(BIO_METHOD *type);
            int  BIO_write(BIO *b, const void *buf, int len);
            void BIO_free(BIO *a);
            X509 *PEM_read_bio_X509(BIO *bp, X509 **x, void *cb, void *u);
            void X509_free(X509 *a);

            int ngx_stream_lua_ffi_socket_tcp_settrustedstore(
                ngx_stream_lua_request_t *r,
                ngx_stream_lua_socket_tcp_upstream_t *u,
                void *store, char **errmsg);
        ]]

        local C = ffi.C

        local function load_store_from_pem(pem)
            local bio = C.BIO_new(C.BIO_s_mem())
            if bio == nil then return nil, "BIO_new failed" end
            if C.BIO_write(bio, pem, #pem) <= 0 then
                C.BIO_free(bio)
                return nil, "BIO_write failed"
            end
            local x509 = C.PEM_read_bio_X509(bio, nil, nil, nil)
            C.BIO_free(bio)
            if x509 == nil then return nil, "PEM_read_bio_X509 failed" end
            local store = C.X509_STORE_new()
            if store == nil then
                C.X509_free(x509)
                return nil, "X509_STORE_new failed"
            end
            if C.X509_STORE_add_cert(store, x509) ~= 1 then
                C.X509_free(x509)
                C.X509_STORE_free(store)
                return nil, "X509_STORE_add_cert failed"
            end
            C.X509_free(x509)
            return ffi.gc(store, C.X509_STORE_free)
        end

        local function settrustedstore(sock, store)
            local base = require "resty.core.base"
            local r = base.get_request()
            if not r then return nil, "no request" end

            local u = sock[1]
            if not u then return nil, "socket not connected" end

            local errmsg = ffi.new("char *[1]")
            local rc = C.ngx_stream_lua_ffi_socket_tcp_settrustedstore(
                r, u, store, errmsg)
            if rc ~= 0 then
                return nil, ffi.string(errmsg[0])
            end
            return true
        end

        local f = assert(io.open("t/cert/mtls_ca.crt"))
        local ca_pem = f:read("*a")
        f:close()

        local store = assert(load_store_from_pem(ca_pem))

        local sock = ngx.socket.tcp()
        sock:settimeout(2000)
        assert(sock:connect("127.0.0.1", $TEST_NGINX_SERVER_SSL_PORT))
        assert(sock:close())

        local ok, err = settrustedstore(sock, store)
        ngx.say("settrustedstore: ", ok, " ", err)
    }

--- user_files eval
">>> mtls_server.key
$::MTLSServerKey
>>> mtls_server.crt
$::MTLSServer
>>> mtls_ca.crt
$::MTLSCA"
--- stream_response
settrustedstore: nil closed
--- no_error_log
[error]
[alert]
[crit]



=== TEST 5: passing a NULL store pointer is accepted
--- stream_config
    server {
        listen $TEST_NGINX_SERVER_SSL_PORT ssl;
        ssl_certificate ../html/mtls_server.crt;
        ssl_certificate_key ../html/mtls_server.key;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            local data = sock:receive()
            if data then
                ngx.say("hello")
            end
        }
    }

--- stream_server_config
    content_by_lua_block {
        local ffi = require "ffi"
        ffi.cdef[[
            typedef struct ngx_stream_lua_request_s       ngx_stream_lua_request_t;
            typedef struct ngx_stream_lua_socket_tcp_upstream_s
                    ngx_stream_lua_socket_tcp_upstream_t;

            int ngx_stream_lua_ffi_socket_tcp_settrustedstore(
                ngx_stream_lua_request_t *r,
                ngx_stream_lua_socket_tcp_upstream_t *u,
                void *store, char **errmsg);
        ]]

        local C = ffi.C

        local function settrustedstore(sock, store)
            local base = require "resty.core.base"
            local r = base.get_request()
            if not r then return nil, "no request" end

            local u = sock[1]
            if not u then return nil, "socket not connected" end

            local errmsg = ffi.new("char *[1]")
            local rc = C.ngx_stream_lua_ffi_socket_tcp_settrustedstore(
                r, u, store, errmsg)
            if rc ~= 0 then
                return nil, ffi.string(errmsg[0])
            end
            return true
        end

        local sock = ngx.socket.tcp()
        sock:settimeout(2000)
        assert(sock:connect("127.0.0.1", $TEST_NGINX_SERVER_SSL_PORT))

        local ok, err = settrustedstore(sock, ffi.cast("void *", 0))
        ngx.say("settrustedstore: ", ok, " ", err)

        sock:close()
    }

--- user_files eval
">>> mtls_server.key
$::MTLSServerKey
>>> mtls_server.crt
$::MTLSServer"
--- stream_response
settrustedstore: true nil
--- no_error_log
[error]
[alert]
[crit]
