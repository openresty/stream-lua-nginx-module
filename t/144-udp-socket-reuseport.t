# vim:set ft= ts=4 sw=4 et fdm=marker:

our $SkipReason;

BEGIN {
    if ($^O ne 'linux') {
        $SkipReason = "SO_REUSEPORT is only supported on Linux";
    }
}

use Test::Nginx::Socket::Lua::Stream $SkipReason ? (skip_all => $SkipReason) : ();

repeat_each(2);

plan tests => blocks() * (repeat_each() * 3);

run_tests();

__DATA__

=== TEST 1: udp socket setoption reuseport sanity
--- stream_config
server {
   listen 127.0.0.1:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "udp reuseport test remote: " .. ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "127.0.0.1"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:setoption("reuseport", true)
      if not ok then
          ngx.log(ngx.ERR, "failed to set reuseport: ", err)
          return
      end

      local ok, err = sock:setpeername(ip, port)
      if not ok then
          ngx.log(ngx.ERR, "failed to setpeername: ", err)
          return
      end

      local ok, err = sock:send("trigger")
      if not ok then
          ngx.log(ngx.ERR, "failed to send: ", err)
      end
  }

--- no_error_log
[error]
--- error_log eval
["stream lua set UDP upstream with REUSEPORT"]



=== TEST 2: udp socket setoption reuseport false
--- stream_config
server {
   listen 127.0.0.1:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "udp reuseport test remote: " .. ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "127.0.0.1"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:setoption("reuseport", false)
      if not ok then
          ngx.log(ngx.ERR, "failed to set reuseport: ", err)
          return
      end

      local ok, err = sock:setpeername(ip, port)
      if not ok then
          ngx.log(ngx.ERR, "failed to setpeername: ", err)
          return
      end

      local ok, err = sock:send("trigger")
      if not ok then
          ngx.log(ngx.ERR, "failed to send: ", err)
      end
  }

--- no_error_log
[error]
--- no_error_log eval
["stream lua set UDP upstream with REUSEPORT"]



=== TEST 3: udp socket setoption reuseport with bind
--- stream_config
server {
   listen 127.0.0.1:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "udp reuseport test remote: " .. ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "127.0.0.1"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:bind(ip)
      if not ok then
          ngx.log(ngx.ERR, "failed to bind: ", err)
          return
      end

      local ok, err = sock:setoption("reuseport", true)
      if not ok then
          ngx.log(ngx.ERR, "failed to set reuseport: ", err)
          return
      end

      local ok, err = sock:setpeername("127.0.0.1", port)
      if not ok then
          ngx.log(ngx.ERR, "failed to setpeername: ", err)
          return
      end

      local ok, err = sock:send("trigger")
      if not ok then
          ngx.log(ngx.ERR, "failed to send: ", err)
      end
  }

--- no_error_log
[error]
--- error_log eval
["lua udp socket bind ip: 127.0.0.1",
"stream lua set UDP upstream with REUSEPORT"]
