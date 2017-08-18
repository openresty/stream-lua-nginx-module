
Name
====

ngx_stream_lua_module - Embed the power of Lua into Nginx stream/TCP Servers.

*This module is not distributed with the Nginx source.* See [the installation instructions](#installation).

Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)
* [Description](#description)
    * [Directives](#directives)
    * [Nginx API for Lua](#nginx-api-for-lua)
* [TODO](#todo)
* [Nginx Compatibility](#nginx-compatibility)
* [Installation](#installation)
* [Community](#community)
    * [English Mailing List](#english-mailing-list)
    * [Chinese Mailing List](#chinese-mailing-list)
* [Code Repository](#code-repository)
* [Bugs and Patches](#bugs-and-patches)
* [Acknowledgments](#acknowledgments)
* [Copyright and License](#copyright-and-license)
* [See Also](#see-also)

Status
======

Experimental.

Synopsis
========

```nginx
events {
    worker_connections 1024;
}

stream {
    # define a TCP server listening on the port 1234:
    server {
        listen 1234;

        content_by_lua_block {
            ngx.say("Hello, Lua!")
        }
    }
}
```

Set up as an SSL TCP server:

```nginx
stream {
    server {
        listen 4343 ssl;

        ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers         AES128-SHA:AES256-SHA:RC4-SHA:DES-CBC3-SHA:RC4-MD5;
        ssl_certificate     /path/to/cert.pem;
        ssl_certificate_key /path/to/cert.key;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;

        content_by_lua_block {
            local sock = assert(ngx.req.socket(true))
            local data = sock:receive()  -- read a line from downstream
            if data == "thunder!" then
                ngx.say("flash!")  -- output data
            else
                ngx.say("boom!")
            end
            ngx.say("the end...")
        }
    }
}
```

Listening on a UNIX domain socket is also supported:

```nginx
stream {
    server {
        listen unix:/tmp/nginx.sock;

        content_by_lua_block {
            ngx.say("What's up?")
            ngx.flush(true)  -- flush any pending output and wait
            ngx.sleep(3)  -- sleeping for 3 sec
            ngx.say("Bye bye...")
        }
    }
}
```

Description
===========

This is a port of the [ngx_http_lua_module](https://github.com/openresty/lua-nginx-module#readme) to the NGINX "stream" subsystem so
as to support generic stream/TCP clients in the downstream.

Lua APIs and directive names rename the same as the `ngx_http_lua_module`.

[Back to TOC](#table-of-contents)

Directives
----------

The following directives are ported directly from `ngx_http_lua_module`. Please check the
documentation of `ngx_http_lua_module` for more details about their usage and behavior.

* [lua_code_cache](https://github.com/openresty/lua-nginx-module#lua_code_cache)
* [lua_regex_cache_max_entries](https://github.com/openresty/lua-nginx-module#lua_regex_cache_max_entries)
* [lua_package_path](https://github.com/openresty/lua-nginx-module#lua_package_path)
* [lua_package_cpath](https://github.com/openresty/lua-nginx-module#lua_package_cpath)
* [init_by_lua_block](https://github.com/openresty/lua-nginx-module#init_by_lua_block)
* [init_by_lua_file](https://github.com/openresty/lua-nginx-module#init_by_lua_file)
* [init_worker_by_lua_block](https://github.com/openresty/lua-nginx-module#init_worker_by_lua_block)
* [init_worker_by_lua_file](https://github.com/openresty/lua-nginx-module#init_worker_by_lua_file)
* [content_by_lua_block](https://github.com/openresty/lua-nginx-module#content_by_lua_block)
* [content_by_lua_file](https://github.com/openresty/lua-nginx-module#content_by_lua_file)
* [lua_shared_dict](https://github.com/openresty/lua-nginx-module#lua_shared_dict)
* [lua_socket_connect_timeout](https://github.com/openresty/lua-nginx-module#lua_socket_connect_timeout)
* [lua_socket_buffer_size](https://github.com/openresty/lua-nginx-module#lua_socket_buffer_size)
* [lua_socket_pool_size](https://github.com/openresty/lua-nginx-module#lua_socket_pool_size)
* [lua_socket_keepalive_timeout](https://github.com/openresty/lua-nginx-module#lua_socket_keepalive_timeout)
* [lua_socket_log_errors](https://github.com/openresty/lua-nginx-module#lua_socket_log_errors)
* [lua_ssl_ciphers](https://github.com/openresty/lua-nginx-module#lua_ssl_ciphers)
* [lua_ssl_crl](https://github.com/openresty/lua-nginx-module#lua_ssl_crl)
* [lua_ssl_protocols](https://github.com/openresty/lua-nginx-module#lua_ssl_protocols)
* [lua_ssl_trusted_certificate](https://github.com/openresty/lua-nginx-module#lua_ssl_trusted_certificate)
* [lua_ssl_verify_depth](https://github.com/openresty/lua-nginx-module#lua_ssl_verify_depth)
* [lua_check_client_abort](https://github.com/openresty/lua-nginx-module#lua_check_client_abort)
* [lua_max_pending_timers](https://github.com/openresty/lua-nginx-module#lua_max_pending_timers)
* [lua_max_running_timers](https://github.com/openresty/lua-nginx-module#lua_max_running_timers)

The [send_timeout](http://nginx.org/r/send_timeout) directive in the Nginx "http" subsystem is missing in the "stream" subsystem.
So `ngx_stream_lua_module` uses the `lua_socket_send_timeout` for this purpose.

[Back to TOC](#table-of-contents)

Nginx API for Lua
-----------------

Many Lua API functions are ported from the `ngx_http_lua_module`. Check out the official manual of
`ngx_http_lua_module` for more details on these Lua API functions.

* [ngx.var.VARIABLE](https://github.com/openresty/lua-nginx-module#ngxvarvariable)

This module fully supports the new variable subsystem inside the NGINX stream core. You may access any
[built-in variables](https://nginx.org/en/docs/stream/ngx_stream_core_module.html#variables) provided by the stream core or
other stream modules.
* [Core constants](https://github.com/openresty/lua-nginx-module#core-constants)

    `ngx.OK`, `ngx.ERROR`, and etc.
* [Nginx log level constants](https://github.com/openresty/lua-nginx-module#nginx-log-level-constants)

    `ngx.ERR`, `ngx.WARN`, and etc.
* [print](https://github.com/openresty/lua-nginx-module#print)
* [ngx.ctx](https://github.com/openresty/lua-nginx-module#ngxctx)
* [ngx.req.socket](https://github.com/openresty/lua-nginx-module#ngxreqsocket)

    Only raw request sockets are supported, for obvious reasons. The `raw` argument value
is ignored and the raw request socket is always returned. Unlike `ngx_http_lua_module`,
you can still call output API functions like `ngx.say`, `ngx.print`, and `ngx.flush`
after acquiring the raw request socket via this function.
* [ngx.print](https://github.com/openresty/lua-nginx-module#ngxprint)
* [ngx.say](https://github.com/openresty/lua-nginx-module#ngxsay)
* [ngx.log](https://github.com/openresty/lua-nginx-module#ngxlog)
* [ngx.flush](https://github.com/openresty/lua-nginx-module#ngxflush)

    This call currently ignores the `wait` argument and always wait for all the pending
output to be completely flushed out (to the system socket send buffers).
* [ngx.exit](https://github.com/openresty/lua-nginx-module#ngxexit)
* [ngx.eof](https://github.com/openresty/lua-nginx-module#ngxeof)
* [ngx.sleep](https://github.com/openresty/lua-nginx-module#ngxsleep)
* [ngx.escape_uri](https://github.com/openresty/lua-nginx-module#ngxescape_uri)
* [ngx.unescape_uri](https://github.com/openresty/lua-nginx-module#ngxunescape_uri)
* [ngx.encode_args](https://github.com/openresty/lua-nginx-module#ngxencode_args)
* [ngx.decode_args](https://github.com/openresty/lua-nginx-module#ngxdecode_args)
* [ngx.encode_base64](https://github.com/openresty/lua-nginx-module#ngxencode_base64)
* [ngx.decode_base64](https://github.com/openresty/lua-nginx-module#ngxdecode_base64)
* [ngx.crc32_short](https://github.com/openresty/lua-nginx-module#ngxcrc32_short)
* [ngx.crc32_long](https://github.com/openresty/lua-nginx-module#ngxcrc32_long)
* [ngx.hmac_sha1](https://github.com/openresty/lua-nginx-module#ngxhmac_sha1)
* [ngx.md5](https://github.com/openresty/lua-nginx-module#ngxmd5)
* [ngx.md5_bin](https://github.com/openresty/lua-nginx-module#ngxmd5_bin)
* [ngx.sha1_bin](https://github.com/openresty/lua-nginx-module#ngxsha1_bin)
* [ngx.quote_sql_str](https://github.com/openresty/lua-nginx-module#ngxquote_sql_str)
* [ngx.today](https://github.com/openresty/lua-nginx-module#ngxtoday)
* [ngx.time](https://github.com/openresty/lua-nginx-module#ngxtime)
* [ngx.now](https://github.com/openresty/lua-nginx-module#ngxnow)
* [ngx.update_time](https://github.com/openresty/lua-nginx-module#ngxupdate_time)
* [ngx.localtime](https://github.com/openresty/lua-nginx-module#ngxlocaltime)
* [ngx.utctime](https://github.com/openresty/lua-nginx-module#ngxutctime)
* [ngx.re.match](https://github.com/openresty/lua-nginx-module#ngxrematch)
* [ngx.re.find](https://github.com/openresty/lua-nginx-module#ngxrefind)
* [ngx.re.gmatch](https://github.com/openresty/lua-nginx-module#ngxregmatch)
* [ngx.re.sub](https://github.com/openresty/lua-nginx-module#ngxresub)
* [ngx.re.gsub](https://github.com/openresty/lua-nginx-module#ngxregsub)
* [ngx.shared.DICT](https://github.com/openresty/lua-nginx-module#ngxshareddict)
* [ngx.socket.tcp](https://github.com/openresty/lua-nginx-module#ngxsockettcp)
* [ngx.socket.udp](https://github.com/openresty/lua-nginx-module#ngxsocketudp)
* [ngx.socket.connect](https://github.com/openresty/lua-nginx-module#ngxsocketconnect)
* [ngx.get_phase](https://github.com/openresty/lua-nginx-module#ngxget_phase)
* [ngx.thread.spawn](https://github.com/openresty/lua-nginx-module#ngxthreadspawn)
* [ngx.thread.wait](https://github.com/openresty/lua-nginx-module#ngxthreadwait)
* [ngx.thread.kill](https://github.com/openresty/lua-nginx-module#ngxthreadkill)
* [ngx.on_abort](https://github.com/openresty/lua-nginx-module#ngxon_abort)
* [ngx.timer.at](https://github.com/openresty/lua-nginx-module#ngxtimerat)
* [ngx.timer.running_count](https://github.com/openresty/lua-nginx-module#ngxtimerrunning_count)
* [ngx.timer.pending_count](https://github.com/openresty/lua-nginx-module#ngxtimerpending_count)
* [ngx.config.debug](https://github.com/openresty/lua-nginx-module#ngxconfigdebug)
* [ngx.config.subsystem](https://github.com/openresty/lua-nginx-module#ngxconfigsubsystem)

    Always takes the Lua string value `"stream"` in this module.
* [ngx.config.prefix](https://github.com/openresty/lua-nginx-module#ngxconfigprefix)
* [ngx.config.nginx_version](https://github.com/openresty/lua-nginx-module#ngxconfignginx_version)
* [ngx.config.nginx_configure](https://github.com/openresty/lua-nginx-module#ngxconfignginx_configure)
* [ngx.config.ngx_lua_version](https://github.com/openresty/lua-nginx-module#ngxconfigngx_lua_version)
* [ngx.worker.exiting](https://github.com/openresty/lua-nginx-module#ngxworkerexiting)
* [ngx.worker.pid](https://github.com/openresty/lua-nginx-module#ngxworkerpid)
* [ngx.worker.count](https://github.com/openresty/lua-nginx-module#ngxworkercount)
* [ngx.worker.id](https://github.com/openresty/lua-nginx-module#ngxworkerid)
* [coroutine.create](https://github.com/openresty/lua-nginx-module#coroutinecreate)
* [coroutine.resume](https://github.com/openresty/lua-nginx-module#coroutineresume)
* [coroutine.yield](https://github.com/openresty/lua-nginx-module#coroutineyield)
* [coroutine.wrap](https://github.com/openresty/lua-nginx-module#coroutinewrap)
* [coroutine.running](https://github.com/openresty/lua-nginx-module#coroutinerunning)
* [coroutine.status](https://github.com/openresty/lua-nginx-module#coroutinestatus)

[Back to TOC](#table-of-contents)

TODO
====

* Add new directives `access_by_lua_block` and `access_by_lua_file`.
* Add new directives `log_by_lua_block` and `log_by_lua_file`.
* Add new directives `balancer_by_lua_block` and `balancer_by_lua_file`.
* Add new directives `ssl_certificate_by_lua_block` and `ssl_certificate_by_lua_file`.
* Port `lua_lingering_close`, `lua_lingering_time` and `lua_lingering_timeout` directives over.
* Add `ngx.semaphore` API.
* Add `ngx_meta_lua_module` to share as much code as possible between this module and `ngx_http_lua_module` and allow sharing
of `lua_shared_dict`.
* Add support for [lua-resty-core](https://github.com/openresty/lua-resty-core).
* Add `lua_postpone_output` to emulate the [postpone_output](http://nginx.org/r/postpone_output) directive.

[Back to TOC](#table-of-contents)

Nginx Compatibility
===================

The latest version of this module is compatible with the following versions of Nginx:

* 1.13.x >= 1.13.3 (last tested: 1.13.3)

Nginx cores older than 1.13.3 (exclusive) are *not* tested and may or may not work. Use at your own risk!

[Back to TOC](#table-of-contents)

Installation
============

This module can be manually compiled into Nginx or OpenResty:

1. Install LuaJIT 2.1 or Lua 5.1 (Lua 5.2+ are *not* supported yet). LuaJIT can be downloaded from the [the LuaJIT project website](http://luajit.org/download.html) and Lua 5.1, from the [Lua project website](http://www.lua.org/).  Some distribution package managers also distribute LuaJIT and/or Lua.
1. Download the latest version of ngx_stream_lua [HERE](https://github.com/openresty/stream-lua-nginx-module/tags).
1. Download the latest supported version of NGINX [HERE](http://nginx.org/) (See [Nginx Compatibility](#nginx-compatibility)) or the OpenResty bundle from [HERE](https://openresty.org/).

Build the source of NGINX or OpenResty with this module, like below:

```bash
wget 'http://nginx.org/download/nginx-1.13.3.tar.gz'
tar -xzvf nginx-1.13.3.tar.gz
cd nginx-1.13.3/

# tell nginx's build system where to find LuaJIT 2.1:
export LUAJIT_LIB=/path/to/luajit/lib
export LUAJIT_INC=/path/to/luajit/include/luajit-2.1

# or tell where to find Lua if using Lua instead:
#export LUA_LIB=/path/to/lua/lib
#export LUA_INC=/path/to/lua/include

# Here we assume Nginx is to be installed under /opt/nginx/.
./configure --prefix=/opt/nginx \
        --with-ld-opt="-Wl,-rpath,/path/to/luajit-or-lua/lib" \
        --with-stream \
        --with-stream_ssl_module \
        --add-module=/path/to/stream-lua-nginx-module

# Build and install
make -j4
make install
```

You may use `--without-http` if you do not wish to use this module with the HTTP subsystem.
ngx_stream_lua will work perfectly fine without the presense of the HTTP subsystem.

[Back to TOC](#table-of-contents)

Community
=========

[Back to TOC](#table-of-contents)

English Mailing List
--------------------

The [openresty-en](https://groups.google.com/group/openresty-en) mailing list is for English speakers.

[Back to TOC](#table-of-contents)

Chinese Mailing List
--------------------

The [openresty](https://groups.google.com/group/openresty) mailing list is for Chinese speakers.

[Back to TOC](#table-of-contents)

Code Repository
===============

The code repository of this project is hosted on github at [openresty/stream-lua-nginx-module](https://github.com/openresty/stream-lua-nginx-module).

[Back to TOC](#table-of-contents)

Bugs and Patches
================

Please submit bug reports, wishlists, or patches by

1. creating a ticket on the [GitHub Issue Tracker](https://github.com/openresty/stream-lua-nginx-module/issues),
1. or posting to the [OpenResty community](#community).

[Back to TOC](#table-of-contents)

Acknowledgments
===============

* We appreciate [Mashape, Inc.](https://www.mashape.com/) for kindly sponsoring [OpenResty Inc.](https://openresty.com/) to make
this module compatible with Nginx core 1.13.3. In addition, they sponsored the work on making code sharing between this module and
[lua-nginx-module](https://github.com/openresty/lua-nginx-module) possible.

Copyright and License
=====================

This module is licensed under the BSD license.

Copyright (C) 2009-2017, by Yichun "agentzh" Zhang (章亦春) <agentzh@gmail.com>, OpenResty Inc.

Copyright (C) 2009-2016, by Xiaozhe Wang (chaoslawful) <chaoslawful@gmail.com>.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)

See Also
========

* [ngx_http_lua_module](https://github.com/openresty/lua-nginx-module)
* [ngx_stream_echo_module](https://github.com/openresty/stream-echo-nginx-module)
* [OpenResty](https://openresty.org/)

[Back to TOC](#table-of-contents)

