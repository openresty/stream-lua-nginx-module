use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);
plan tests => repeat_each() * blocks() * 3;

$ENV{TEST_NGINX_HTML_DIR} ||= html_dir();

add_block_preprocessor(sub {
    my $block = shift;
    my $protocol = $block->tls_protocol;
    chomp $protocol;
    my $preference = $block->preference;
    chomp $preference;
    my ($method, $server_ciphers, $client_config);

    if ($protocol eq 'TLSv1.2') {
        $method = 'set_ciphers';
        $server_ciphers = 'ECDHE-RSA-AES128-GCM-SHA256:'
                          . 'ECDHE-RSA-AES256-GCM-SHA384';
        $client_config = 'lua_ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:'
                         . 'ECDHE-RSA-AES128-GCM-SHA256;';

    } else {
        $method = 'set_ciphersuites';
        $server_ciphers = 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384';
        $client_config = 'lua_ssl_conf_command Ciphersuites '
                         . 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256;';
    }

    my $first_call = '';
    if ($block->toggle) {
        $first_call = <<EOC;
            local ok, err = ssl_clt.$method("$server_ciphers", true)
            if not ok then
                error(err)
            end
EOC
    }

    $block->set_value('stream_config', <<EOC);
    server {
        listen unix:$ENV{TEST_NGINX_HTML_DIR}/nginx.sock ssl;
        ssl_protocols $protocol;
        ssl_prefer_server_ciphers on;
        ssl_certificate ../../cert/test.crt;
        ssl_certificate_key ../../cert/test.key;

        ssl_client_hello_by_lua_block {
            local ssl_clt = require "ngx.ssl.clienthello"
$first_call
            local ok, err = ssl_clt.$method("$server_ciphers", $preference)
            if not ok then
                error(err)
            end
        }

        content_by_lua_block {
            ngx.say(ngx.var.ssl_cipher)
        }
    }
EOC

    $block->set_value('stream_server_config', <<EOC);
    lua_ssl_protocols $protocol;
    $client_config

    content_by_lua_block {
        local sock = ngx.socket.tcp()
        sock:settimeout(2000)
        local ok, err = sock:connect("unix:$ENV{TEST_NGINX_HTML_DIR}/nginx.sock")
        if not ok then
            error(err)
        end

        local session, err = sock:sslhandshake(false, "test.com", false)
        if not session then
            error(err)
        end

        local cipher, err = sock:receive()
        if not cipher then
            error(err)
        end

        ngx.say(cipher)
        sock:close()
    }
EOC
});

no_long_string();
run_tests();

__DATA__

=== TEST 1: TLS 1.2 false overrides inherited server preference
--- tls_protocol: TLSv1.2
--- preference: false
--- stream_response
ECDHE-RSA-AES256-GCM-SHA384
--- no_error_log
[error]



=== TEST 2: TLS 1.2 can disable server preference after enabling it
--- tls_protocol: TLSv1.2
--- preference: false
--- toggle: 1
--- stream_response
ECDHE-RSA-AES256-GCM-SHA384
--- no_error_log
[error]



=== TEST 3: TLS 1.2 true still selects the server preference
--- tls_protocol: TLSv1.2
--- preference: true
--- stream_response
ECDHE-RSA-AES128-GCM-SHA256
--- no_error_log
[error]



=== TEST 4: TLS 1.3 false overrides inherited server preference
--- tls_protocol: TLSv1.3
--- preference: false
--- stream_response
TLS_AES_256_GCM_SHA384
--- no_error_log
[error]



=== TEST 5: TLS 1.3 can disable server preference after enabling it
--- tls_protocol: TLSv1.3
--- preference: false
--- toggle: 1
--- stream_response
TLS_AES_256_GCM_SHA384
--- no_error_log
[error]



=== TEST 6: TLS 1.3 true still selects the server preference
--- tls_protocol: TLSv1.3
--- preference: true
--- stream_response
TLS_AES_128_GCM_SHA256
--- no_error_log
[error]
