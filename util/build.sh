#!/usr/bin/env bash

# this script is for module developers.
# the ngx-build script comes from the nginx-devel-utils project on GitHub:
#
#       https://github.com/openresty/nginx-devel-utils

root=`pwd`
version=$1
force=$2
home=~

if [ -z "$version" ]; then
    echo "Usage: $0 <nginx-version> [force]"
    exit 1
fi

add_http3_module=--with-http_v3_module
answer=`$root/util/ver-ge "$version" 1.25.1`
if [ "$OPENSSL_VER" = "1.1.0l" ] || [ "$answer" = "N" ]; then
    add_http3_module=""
fi

disable_pcre2=--without-pcre2
answer=`$root/util/ver-ge "$version" 1.25.1`
if [ "$answer" = "N" ] || [ "$USE_PCRE2" = "Y" ]; then
    disable_pcre2=""
fi
if [ "$USE_PCRE2" = "Y" ]; then
    PCRE_INC=$PCRE2_INC
    PCRE_LIB=$PCRE2_LIB
fi

            #--add-module=$root/../stream-echo-nginx-module \
ngx-build $force $version \
            --with-cc-opt="-DNGX_LUA_USE_ASSERT -I$PCRE_INC -I$OPENSSL_INC" \
            --with-ld-opt="-L$PCRE_LIB -L$OPENSSL_LIB -Wl,-rpath,$PCRE_LIB:$LIBDRIZZLE_LIB:$OPENSSL_LIB" \
            --with-http_stub_status_module \
            --with-http_image_filter_module \
            $add_http3_module \
            $disable_pcre2 \
            --with-http_ssl_module \
            --without-mail_pop3_module \
            --without-mail_imap_module \
            --without-mail_smtp_module \
            --without-http_upstream_ip_hash_module \
            --without-http_memcached_module \
            --without-http_referer_module \
            --without-http_autoindex_module \
            --without-http_auth_basic_module \
            --without-http_userid_module \
            --with-stream_ssl_module \
            --with-stream \
            --with-stream_ssl_preread_module \
            --with-ipv6 \
            --add-module=$root/../lua-nginx-module \
            --add-module=$root/../echo-nginx-module \
            --add-module=$root/../memc-nginx-module \
            --add-module=$root/../headers-more-nginx-module \
            --add-module=$root $opts \
            --with-poll_module \
            --without-http_ssi_module \
            --with-debug || exit 1
