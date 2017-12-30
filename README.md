
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

The API is still in flux and may change without notice.

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
* [preread_by_lua_block](#preread_by_lua_block)
* [preread_by_lua_file](#preread_by_lua_file)
* [content_by_lua_block](https://github.com/openresty/lua-nginx-module#content_by_lua_block)
* [content_by_lua_file](https://github.com/openresty/lua-nginx-module#content_by_lua_file)
* [balancer_by_lua_block](https://github.com/openresty/lua-nginx-module#balancer_by_lua_block)
* [balancer_by_lua_file](https://github.com/openresty/lua-nginx-module#balancer_by_lua_file)
* [log_by_lua_block](#log_by_lua_block)
* [log_by_lua_file](#log_by_lua_file)
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
* [lua_add_variable](#lua_add_variable)

The [send_timeout](http://nginx.org/r/send_timeout) directive in the Nginx "http" subsystem is missing in the "stream" subsystem.
So `ngx_stream_lua_module` uses the `lua_socket_send_timeout` for this purpose.

**Note:** the lingering close directive that used to exist in older version of stream_lua_nginx_module has been removed and can
now be simulated with the newly added [tcpsock:shutdown](#tcpsockshutdown) method if necessary.

[Back to TOC](#table-of-contents)

preread_by_lua_block
--------------------

**syntax:** *preread_by_lua_block { lua-script }*

**context:** *stream, server*

**phase:** *preread*

Acts as a rewrite phase handler and executes Lua code string specified in `lua-script` for every connection
(or packet in datagram mode).
The Lua code may make [API calls](#nginx-api-for-lua) and is executed as a new spawned coroutine in an independent global environment (i.e. a sandbox).

It is possible to acquire raw request socket using [ngx.req.socket](https://github.com/openresty/lua-nginx-module#ngxreqsocket)
and receive data from or send data to the client. However, keep in mind that calling the `receive()` method
of the request socket will consume the data from the buffer and those data will not be seen by handlers
further down the chain.

This directive was first introduced in the `v0.0.3` release.

[Back to TOC](#directives)

preread_by_lua_file
--------------------

**syntax:** *preread_by_lua_file &lt;path-to-lua-script-file&gt;*

**context:** *stream, server*

**phase:** *preread*

Equivalent to [preread_by_lua_block](#preread_by_lua_block), except that the file specified by `<path-to-lua-script-file>` contains the Lua code
or LuaJIT bytecode to be executed.

Nginx variables can be used in the `<path-to-lua-script-file>` string to provide flexibility. This however carries some risks and is not ordinarily recommended.

When a relative path like `foo/bar.lua` is given, they will be turned into the absolute path relative to the `server prefix` path determined by the `-p PATH` command-line option while starting the Nginx server.

When the Lua code cache is turned on (by default), the user code is loaded once at the first request and cached and the Nginx config must be reloaded each time the Lua source file is modified. The Lua code cache can be temporarily disabled during development by switching [lua_code_cache](#lua_code_cache) `off` in `nginx.conf` to avoid reloading Nginx.

This directive was first introduced in the `v0.0.3` release.

[Back to TOC](#directives)

log_by_lua_block
--------------------

**syntax:** *log_by_lua_block { lua-script }*

**context:** *stream, server*

**phase:** *log*

Runs the Lua source code inlined as the `<lua-script-str>` at the `log` request processing phase. This does not replace the current access logs, but runs before.

Yielding APIs in this phase, such as `ngx.req.socket`, `ngx.socket.*`, `ngx.sleep`, `ngx.say` are **not** available in this phase.

This directive was first introduced in the `v0.0.3` release.

[Back to TOC](#directives)

log_by_lua_file
--------------------

**syntax:** *preread_by_lua_file &lt;path-to-lua-script-file&gt;*

**context:** *stream, server*

**phase:** *log*

Equivalent to [log_by_lua_block](#log_by_lua_block), except that the file specified by `<path-to-lua-script-file>` contains the Lua code
or LuaJIT bytecode to be executed.

Nginx variables can be used in the `<path-to-lua-script-file>` string to provide flexibility. This however carries some risks and is not ordinarily recommended.

When a relative path like `foo/bar.lua` is given, they will be turned into the absolute path relative to the `server prefix` path determined by the `-p PATH` command-line option while starting the Nginx server.

When the Lua code cache is turned on (by default), the user code is loaded once at the first request and cached and the Nginx config must be reloaded each time the Lua source file is modified. The Lua code cache can be temporarily disabled during development by switching [lua_code_cache](#lua_code_cache) `off` in `nginx.conf` to avoid reloading Nginx.

This directive was first introduced in the `v0.0.3` release.

[Back to TOC](#directives)

lua_add_variable
----------------

**syntax:** *lua_add_variable $var*

**context:** *stream*

Add variable `$var` to the stream subsystem and makes it changeable. If `$var` already exists,
this directive will do nothing.

By default, variables added using this directive are considered "not found" and reading them
using `ngx.var` will return `nil`. However, they could be re-assigned using `ngx.var` code at any time.

This directive was first introduced in the `v0.0.x` release.

[Back to TOC](#directives)

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
* [ngx.balancer](https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/balancer.md)

Only raw request sockets are supported, for obvious reasons. The `raw` argument value
is ignored and the raw request socket is always returned. Unlike `ngx_http_lua_module`,
you can still call output API functions like `ngx.say`, `ngx.print`, and `ngx.flush`
after acquiring the raw request socket via this function.

Raw request socket returned by this module will contain the following extra method:

tcpsock:shutdown
----------------
**syntax:** *ok, err = tcpsock:shutdown("send")*

**context:** *content_by_lua&#42;*

Shuts down the write part of the request socket, prevents all further writing to the client
and sends TCP FIN, while keeping the reading half open.

Currently only the `"send"` direction is supported. Using any parameters other than "send" will return
an error.

If you called any output functions (like [ngx.say](https://github.com/openresty/lua-nginx-module#ngxsay))
before calling this method, consider use `ngx.flush(true)` to make sure all busy buffers are complely
flushed before shutting down the socket. If any busy buffers were detected, this method will return `nil`
will error message `"socket busy writing"`.

This feature is particularly useful for protocols that generates response before actually
finishes consuming all incoming data. Normally Kernel will send out RST to the client when
[tcpsock:close](https://github.com/openresty/lua-nginx-module#tcpsockclose) is called without
emptying the receiving buffer first. Calling this method will allow you to keep reading from
the receiving buffer and prevents RST from being sent.

You can also use this method to simulate lingering close similar to that
[provided by the ngx_http_core_module](https://nginx.org/en/docs/http/ngx_http_core_module.html#lingering_close)
for protocols that needs such behavior. Here is an example:

```lua
local LINGERING_TIME = 30 -- 30 seconds
local LINGERING_TIMEOUT = 5000 -- 5 seconds

local ok, err = sock:shutdown("send")
if not ok then
    ngx.log(ngx.ERR, "failed to shutdown: ", err)
    return
end

local deadline = ngx.time() + LINGERING_TIME

sock:settimeouts(nil, nil, LINGERING_TIMEOUT)

repeat
    local data, _, partial = sock:receive(1024)
until (not data and not partial) or ngx.time() >= deadline
```

[Back to TOC](#directives)

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
* Add new directives `ssl_certificate_by_lua_block` and `ssl_certificate_by_lua_file`.
* Add `ngx.semaphore` API.
* Add support for [lua-resty-core](https://github.com/openresty/lua-resty-core).
* Add `lua_postpone_output` to emulate the [postpone_output](http://nginx.org/r/postpone_output) directive.

[Back to TOC](#table-of-contents)

Nginx Compatibility
===================

The latest version of this module is compatible with the following versions of Nginx:

* 1.13.x >= 1.13.3 (last tested: 1.13.6)

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
[lua-nginx-module](https://github.com/openresty/lua-nginx-module), as well as balancer_by_lua_*, preread_by_lua_* and log_by_lua_* support possible.

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

