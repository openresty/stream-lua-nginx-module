# vim:set ft= ts=4 sw=4 et fdm=marker:

our $SkipReason;

BEGIN {
    if ( !$ENV{NGX_HAVE_TRANSPARENT_PROXY}) {
        $SkipReason = "Not a transparent proxy build";
    }
}

use Test::Nginx::Socket::Lua::Stream $SkipReason ? (skip_all => $SkipReason) : ();

repeat_each(1);

plan tests => blocks() * (repeat_each() * 3 + 1);

run_tests();

__DATA__

=== TEST 1: tcp ip_transparent sanity
--- stream_config
server {
   listen 127.0.0.1:2986;
   content_by_lua_block {
     ngx.say(ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "127.0.0.1"
      local port = 2986
      local sock = ngx.socket.tcp()

      local ok, err = sock:setoption(ngx.IP_TRANSPARENT)
      if not ok then
          ngx.log(ngx.ERR, err)
      end

      local ok, err = sock:connect(ip, port)
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end

      local line, err, part = sock:receive()
      if line then
          ngx.say(line)
      else
          ngx.log(ngx.ERR, err)
      end
  }

--- stream_response
127.0.0.1
--- no_error_log
[error]
--- error_log eval
["stream lua set TCP upstream with IP_TRANSPARENT"]


=== TEST 2: udp ip_transparent sanity
--- stream_config
server {
   listen 127.0.0.1:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "remote udp address: " .. ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "127.0.0.1"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:setoption(ngx.IP_TRANSPARENT)
      if not ok then
          ngx.log(ngx.ERR, err)
      end

      local ok, err = sock:setpeername(ip, port)
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end

      local ok, err = sock:send("trigger")
      if not ok then
          ngx.log(ngx.ERR, err)
      end
  }

--- no_error_log
[error]
--- error_log eval
["stream lua set UDP upstream with IP_TRANSPARENT", "remote udp address: 127.0.0.1"]
