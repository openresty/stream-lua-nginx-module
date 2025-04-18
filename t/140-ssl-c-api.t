# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;
repeat_each(3);

# All these tests need to have new openssl
my $NginxBinary = $ENV{'TEST_NGINX_BINARY'} || 'nginx';
my $openssl_version = eval { `$NginxBinary -V 2>&1` };

if ($openssl_version =~ m/built with OpenSSL (0|1\.0\.(?:0|1[^\d]|2[a-d]).*)/) {
    plan(skip_all => "too old OpenSSL, need 1.0.2e, was $1");
} else {
    plan tests => repeat_each() * (blocks() * 5 - 1);
}

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

#log_level 'warn';
log_level 'debug';

no_long_string();
#no_diff();

add_block_preprocessor(sub {
    my $block = shift;

    if (!defined $block->user_files) {
        $block->set_value("user_files", <<'_EOC_');
>>> defines.lua
local ffi = require "ffi"

ffi.cdef[[
    int ngx_stream_lua_ffi_cert_pem_to_der(const unsigned char *pem,
        size_t pem_len, unsigned char *der, char **err);

    int ngx_stream_lua_ffi_priv_key_pem_to_der(const unsigned char *pem,
        size_t pem_len, const unsigned char *passphrase,
        unsigned char *der, char **err);

    int ngx_stream_lua_ffi_ssl_set_der_certificate(void *r,
        const char *data, size_t len, char **err);

    int ngx_stream_lua_ffi_ssl_set_der_private_key(void *r,
        const char *data, size_t len, char **err);

    int ngx_stream_lua_ffi_ssl_clear_certs(void *r, char **err);

    void *ngx_stream_lua_ffi_parse_pem_cert(const unsigned char *pem,
        size_t pem_len, char **err);

    void *ngx_stream_lua_ffi_parse_der_cert(const unsigned char *der,
        size_t der_len, char **err);

    void *ngx_stream_lua_ffi_parse_pem_priv_key(const unsigned char *pem,
        size_t pem_len, char **err);

    void *ngx_stream_lua_ffi_parse_der_priv_key(const unsigned char *der,
        size_t der_len, char **err);

    int ngx_stream_lua_ffi_set_cert(void *r,
        void *cdata, char **err);

    int ngx_stream_lua_ffi_set_priv_key(void *r,
        void *cdata, char **err);

    void ngx_stream_lua_ffi_free_cert(void *cdata);

    void ngx_stream_lua_ffi_free_priv_key(void *cdata);

    int ngx_stream_lua_ffi_ssl_verify_client(void *r, void *cdata, void *cdata, int depth, char **err);

    int ngx_stream_lua_ffi_ssl_client_random(ngx_stream_lua_request_t *r,
        unsigned char *out, size_t *outlen, char **err);

]]
_EOC_
    }

    my $stream_config = $block->stream_config || '';
    $stream_config .= <<'_EOC_';
lua_package_path "$prefix/html/?.lua;../lua-resty-core/lib/?.lua;;";
_EOC_
    $block->set_value("stream_config", $stream_config);
});

run_tests();

__DATA__

=== TEST 1: simple cert + private key
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            require "defines"
            local ffi = require "ffi"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            ffi.C.ngx_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test.crt", "rb"))
            local cert = f:read("*all")
            f:close()

            local out = ffi.new("char [?]", #cert)

            local rc = ffi.C.ngx_stream_lua_ffi_cert_pem_to_der(cert, #cert, out, errmsg)
            if rc < 1 then
                ngx.log(ngx.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local cert_der = ffi.string(out, rc)

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_set_der_certificate(r, cert_der, #cert_der, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set DER cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            f = assert(io.open("t/cert/test.key", "rb"))
            local pkey = f:read("*all")
            f:close()

            out = ffi.new("char [?]", #pkey)

            local rc = ffi.C.ngx_stream_lua_ffi_priv_key_pem_to_der(pkey, #pkey, nil, out, errmsg)
            if rc < 1 then
                ngx.log(ngx.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local pkey_der = ffi.string(out, rc)

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_set_der_private_key(r, pkey_der, #pkey_der, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set DER priv key: ",
                        ffi.string(errmsg[0]))
                return
            end
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test.crt;

    content_by_lua_block {
        do
            local sock = ngx.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                ngx.say("failed to do SSL handshake: ", err)
                return
            end

            ngx.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- ngx.say("failed to receive response status line: ", err)
                    break
                end

                ngx.say("received: ", line)
            end

            local ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 2: ECDSA cert + private key
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            ffi.C.ngx_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test_ecdsa.crt", "rb"))
            local cert = f:read("*all")
            f:close()

            local out = ffi.new("char [?]", #cert)

            local rc = ffi.C.ngx_stream_lua_ffi_cert_pem_to_der(cert, #cert, out, errmsg)
            if rc < 1 then
                ngx.log(ngx.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local cert_der = ffi.string(out, rc)

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_set_der_certificate(r, cert_der, #cert_der, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set DER cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            f = assert(io.open("t/cert/test_ecdsa.key", "rb"))
            local pkey = f:read("*all")
            f:close()

            out = ffi.new("char [?]", #pkey)

            local rc = ffi.C.ngx_stream_lua_ffi_priv_key_pem_to_der(pkey, #pkey, nil, out, errmsg)
            if rc < 1 then
                ngx.log(ngx.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local pkey_der = ffi.string(out, rc)

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_set_der_private_key(r, pkey_der, #pkey_der, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set DER priv key: ",
                        ffi.string(errmsg[0]))
                return
            end
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test_ecdsa.crt;

    content_by_lua_block {
        do
            local sock = ngx.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                ngx.say("failed to do SSL handshake: ", err)
                return
            end

            ngx.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- ngx.say("failed to receive response status line: ", err)
                    break
                end

                ngx.say("received: ", line)
            end

            local ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 3: Handshake continue when cert_pem_to_der errors
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            local cert = "garbage data"

            local out = ffi.new("char [?]", #cert)

            local rc = ffi.C.ngx_stream_lua_ffi_cert_pem_to_der(cert, #cert, out, errmsg)
            if rc < 1 then
                ngx.log(ngx.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
            end

            local pkey = "garbage key data"

            out = ffi.new("char [?]", #pkey)

            local rc = ffi.C.ngx_stream_lua_ffi_priv_key_pem_to_der(pkey, #pkey, nil, out, errmsg)
            if rc < 1 then
                ngx.log(ngx.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
            end
        }

        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test.crt;

    content_by_lua_block {
        do
            local sock = ngx.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                ngx.say("failed to do SSL handshake: ", err)
                return
            end

            ngx.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- ngx.say("failed to receive response status line: ", err)
                    break
                end

                ngx.say("received: ", line)
            end

            local ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"
failed to parse PEM cert: PEM_read_bio_X509_AUX()
failed to parse PEM priv key: PEM_read_bio_PrivateKey() failed

--- no_error_log
[alert]



=== TEST 4: simple cert + private key cdata
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            ffi.C.ngx_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local cert = ffi.C.ngx_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not cert then
                ngx.log(ngx.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_set_cert(r, cert, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_cert(cert)

            f = assert(io.open("t/cert/test.key", "rb"))
            local pkey_data = f:read("*all")
            f:close()

            local pkey = ffi.C.ngx_stream_lua_ffi_parse_pem_priv_key(pkey_data, #pkey_data, errmsg)
            if pkey == nil then
                ngx.log(ngx.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_set_priv_key(r, pkey, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_priv_key(pkey)
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test.crt;

    content_by_lua_block {
        do
            local sock = ngx.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                ngx.say("failed to do SSL handshake: ", err)
                return
            end

            ngx.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- ngx.say("failed to receive response status line: ", err)
                    break
                end

                ngx.say("received: ", line)
            end

            local ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 5: ECDSA cert + private key cdata
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            ffi.C.ngx_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test_ecdsa.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local cert = ffi.C.ngx_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not cert then
                ngx.log(ngx.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_set_cert(r, cert, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_cert(cert)

            f = assert(io.open("t/cert/test_ecdsa.key", "rb"))
            local pkey_data = f:read("*all")
            f:close()

            local pkey = ffi.C.ngx_stream_lua_ffi_parse_pem_priv_key(pkey_data, #pkey_data, errmsg)
            if pkey == nil then
                ngx.log(ngx.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_set_priv_key(r, pkey, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_priv_key(pkey)
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test_ecdsa.crt;

    content_by_lua_block {
        do
            local sock = ngx.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                ngx.say("failed to do SSL handshake: ", err)
                return
            end

            ngx.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- ngx.say("failed to receive response status line: ", err)
                    break
                end

                ngx.say("received: ", line)
            end

            local ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 6: verify client with CA certificates
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            local f = assert(io.open("t/cert/test.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local cert = ffi.C.ngx_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not cert then
                ngx.log(ngx.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_verify_client(r, cert, nil, -1, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_cert(cert)
        }

        content_by_lua_block {
            print('client certificate subject: ', ngx.var.ssl_client_s_dn)
            ngx.say(ngx.var.ssl_client_verify)
        }
    }
--- stream_server_config
    proxy_pass                  unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                   on;
    proxy_ssl_certificate       ../../cert/test.crt;
    proxy_ssl_certificate_key   ../../cert/test.key;
    proxy_ssl_session_reuse     off;

--- stream_response
SUCCESS

--- error_log
client certificate subject: emailAddress=agentzh@gmail.com,CN=test.com

--- no_error_log
[error]
[alert]



=== TEST 7: verify client without CA certificates
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_verify_client(r, nil, nil, -1, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end
        }

        content_by_lua_block {
            print('client certificate subject: ', ngx.var.ssl_client_s_dn)
            ngx.say(ngx.var.ssl_client_verify)
        }
    }
--- stream_server_config
    proxy_pass                  unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                   on;
    proxy_ssl_certificate       ../../cert/test.crt;
    proxy_ssl_certificate_key   ../../cert/test.key;
    proxy_ssl_session_reuse     off;

--- stream_response eval
qr/FAILED:self[- ]signed certificate/

--- error_log
client certificate subject: emailAddress=agentzh@gmail.com,CN=test.com

--- no_error_log
[error]
[alert]



=== TEST 8: verify client but client provides no certificate
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            local f = assert(io.open("t/cert/test.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local cert = ffi.C.ngx_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not cert then
                ngx.log(ngx.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_verify_client(r, cert, nil, 1, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_cert(cert)
        }

        content_by_lua_block {
            print('client certificate subject: ', ngx.var.ssl_client_s_dn)
            ngx.say(ngx.var.ssl_client_verify)
        }
    }
--- stream_server_config
    proxy_pass                  unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                   on;
    proxy_ssl_session_reuse     off;

--- stream_response
NONE

--- error_log
client certificate subject: nil

--- no_error_log
[error]
[alert]



=== TEST 9: private key protected by passphrase
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            require "defines"
            local ffi = require "ffi"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            ffi.C.ngx_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test.crt", "rb"))
            local cert = f:read("*all")
            f:close()

            local out = ffi.new("char [?]", #cert)

            local rc = ffi.C.ngx_stream_lua_ffi_cert_pem_to_der(cert, #cert, out, errmsg)
            if rc < 1 then
                ngx.log(ngx.ERR, "failed to parse PEM cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local cert_der = ffi.string(out, rc)

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_set_der_certificate(r, cert_der, #cert_der, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set DER cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            f = assert(io.open("t/cert/test.key", "rb"))
            local pkey = f:read("*all")
            f:close()

            out = ffi.new("char [?]", #pkey)

            local rc = ffi.C.ngx_stream_lua_ffi_priv_key_pem_to_der(pkey, #pkey, "123456", out, errmsg)
            if rc < 1 then
                ngx.log(ngx.ERR, "failed to parse PEM priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local pkey_der = ffi.string(out, rc)

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_set_der_private_key(r, pkey_der, #pkey_der, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set DER priv key: ",
                        ffi.string(errmsg[0]))
                return
            end
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test.crt;

    content_by_lua_block {
        do
            local sock = ngx.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                ngx.say("failed to do SSL handshake: ", err)
                return
            end

            ngx.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- ngx.say("failed to receive response status line: ", err)
                    break
                end

                ngx.say("received: ", line)
            end

            local ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 10: DER cert + private key cdata
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            ffi.C.ngx_stream_lua_ffi_ssl_clear_certs(r, errmsg)

            local f = assert(io.open("t/cert/test_der.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local cert = ffi.C.ngx_stream_lua_ffi_parse_der_cert(cert_data, #cert_data, errmsg)
            if not cert then
                ngx.log(ngx.ERR, "failed to parse DER cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_set_cert(r, cert, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_cert(cert)

            f = assert(io.open("t/cert/test_der.key", "rb"))
            local pkey_data = f:read("*all")
            f:close()

            local pkey = ffi.C.ngx_stream_lua_ffi_parse_der_priv_key(pkey_data, #pkey_data, errmsg)
            if pkey == nil then
                ngx.log(ngx.ERR, "failed to parse DER priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_set_priv_key(r, pkey, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata priv key: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_priv_key(pkey)
        }

        ssl_certificate ../../cert/test2.crt;
        ssl_certificate_key ../../cert/test2.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test.crt;

    content_by_lua_block {
        do
            local sock = ngx.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                ngx.say("failed to do SSL handshake: ", err)
                return
            end

            ngx.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- ngx.say("failed to receive response status line: ", err)
                    break
                end

                ngx.say("received: ", line)
            end

            local ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 11: client random
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            -- test client random length
            local out = ffi.new("unsigned char[?]", 0)
            local sizep = ffi.new("size_t[1]", 0)

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_client_random(r, out, sizep, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to get client random length: ",
                        ffi.string(errmsg[0]))
                return
            end

            if tonumber(sizep[0]) ~= 32 then
                ngx.log(ngx.ERR, "client random length does not equal 32")
                return
            end

            -- test client random value
            out = ffi.new("unsigned char[?]", 50)
            sizep = ffi.new("size_t[1]", 50)

            rc = ffi.C.ngx_stream_lua_ffi_ssl_client_random(r, out, sizep, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to get client random: ",
                        ffi.string(errmsg[0]))
                return
            end

            local init_v = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
            if ffi.string(out, sizep[0]) == init_v then
                ngx.log(ngx.ERR, "maybe the client random value is incorrect")
                return
            end
        }

        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        return 'it works!\n';
    }
--- stream_server_config
    lua_ssl_trusted_certificate ../../cert/test.crt;

    content_by_lua_block {
        do
            local sock = ngx.socket.tcp()

            sock:settimeout(2000)

            local ok, err = sock:connect("unix:$TEST_NGINX_HTML_DIR/nginx.sock")
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say("connected: ", ok)

            local sess, err = sock:sslhandshake(nil, "test.com", true)
            if not sess then
                ngx.say("failed to do SSL handshake: ", err)
                return
            end

            ngx.say("ssl handshake: ", type(sess))

            while true do
                local line, err = sock:receive()
                if not line then
                    -- ngx.say("failed to receive response status line: ", err)
                    break
                end

                ngx.say("received: ", line)
            end

            local ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        end  -- do
        -- collectgarbage()
    }

--- stream_response
connected: 1
ssl handshake: userdata
received: it works!
close: 1 nil

--- error_log
lua ssl server name: "test.com"

--- no_error_log
[error]
[alert]



=== TEST 12: verify client, but server don't trust root ca
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            local f = assert(io.open("t/cert/mtls_server.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local client_certs = ffi.C.ngx_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not client_certs then
                ngx.log(ngx.ERR, "failed to parse PEM client certs: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_verify_client(r, client_certs, nil, 1, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_cert(client_certs)
        }

        content_by_lua_block {
            ngx.say(ngx.var.ssl_client_verify)
        }
    }
--- stream_server_config
    proxy_pass                  unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                   on;
    proxy_ssl_certificate       ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key   ../../cert/mtls_client.key;
    proxy_ssl_session_reuse     off;

--- stream_response
FAILED:unable to verify the first certificate

--- no_error_log
[error]
[alert]



=== TEST 13: verify client and server trust root ca
--- stream_config
    server {
        listen unix:$TEST_NGINX_HTML_DIR/nginx.sock ssl;

        ssl_certificate ../../cert/mtls_server.crt;
        ssl_certificate_key ../../cert/mtls_server.key;

        ssl_certificate_by_lua_block {
            collectgarbage()

            local ffi = require "ffi"
            require "defines"

            local errmsg = ffi.new("char *[1]")

            local r = require "resty.core.base" .get_request()
            if not r then
                ngx.log(ngx.ERR, "no request found")
                return
            end

            local f = assert(io.open("t/cert/mtls_server.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local client_certs = ffi.C.ngx_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not client_certs then
                ngx.log(ngx.ERR, "failed to parse PEM client certs: ",
                        ffi.string(errmsg[0]))
                return
            end

            local f = assert(io.open("t/cert/mtls_ca.crt", "rb"))
            local cert_data = f:read("*all")
            f:close()

            local trusted_certs = ffi.C.ngx_stream_lua_ffi_parse_pem_cert(cert_data, #cert_data, errmsg)
            if not trusted_certs then
                ngx.log(ngx.ERR, "failed to parse PEM trusted certs: ",
                        ffi.string(errmsg[0]))
                return
            end

            local rc = ffi.C.ngx_stream_lua_ffi_ssl_verify_client(r, client_certs, trusted_certs, 1, errmsg)
            if rc ~= 0 then
                ngx.log(ngx.ERR, "failed to set cdata cert: ",
                        ffi.string(errmsg[0]))
                return
            end

            ffi.C.ngx_stream_lua_ffi_free_cert(client_certs)
            ffi.C.ngx_stream_lua_ffi_free_cert(trusted_certs)
        }

        content_by_lua_block {
            ngx.say(ngx.var.ssl_client_verify)
        }
    }
--- stream_server_config
    proxy_pass                  unix:$TEST_NGINX_HTML_DIR/nginx.sock;
    proxy_ssl                   on;
    proxy_ssl_certificate       ../../cert/mtls_client.crt;
    proxy_ssl_certificate_key   ../../cert/mtls_client.key;
    proxy_ssl_session_reuse     off;

--- stream_response
SUCCESS

--- no_error_log
[error]
[alert]
