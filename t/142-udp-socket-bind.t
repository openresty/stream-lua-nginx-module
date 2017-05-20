
use Test::Nginx::Socket::Lua::Stream;

repeat_each(2);
#repeat_each(1);

plan tests => repeat_each() * (blocks() * 3 + 4);

my $local_ip = `ifconfig | grep -oE 'addr:([0-9]{1,3}+\\.){3}[0-9]{1,3}' | sed -e 's/addr://' | grep -v '127.0.0.1' | head -n 1`;
chomp $local_ip;

my $local_domain_server = `dig something | grep -oE ' ([0-9]{1,3}+\\.){3}[0-9]{1,3}'`;
chomp $local_domain_server;
$ENV{TEST_NGINX_LOCAL_DOMAIN_SERVER} ||= $local_domain_server;
$ENV{TEST_NGINX_SERVER_IP} ||= $local_ip;
$ENV{TEST_NGINX_NOT_EXIST_IP} ||= '8.8.8.8';
$ENV{TEST_NGINX_INVALID_IP} ||= '127.0.0.1:8899';

no_long_string();
#no_diff();
#log_level 'warn';
no_shuffle();

run_tests();

__DATA__

=== TEST 1: upstream sockets bind 127.0.0.1
--- stream_config
server {
   listen 127.0.1.2:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "udp bind address: " .. ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "127.0.0.1"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:bind(ip)
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end

      local ok, err = sock:setpeername("127.0.1.2", port)
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
["lua udp socket bind ip: 127.0.0.1",
"udp bind address: 127.0.0.1 while handling client connection, udp client: 127.0.0.1, server: 127.0.1.2:2986"]


=== TEST 2: upstream sockets bind non loopback ip
--- stream_config
server {
   listen 127.0.1.2:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "udp bind address: " .. ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "$TEST_NGINX_SERVER_IP"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:bind(ip)
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end

      local ok, err = sock:setpeername("127.0.1.2", port)
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
["lua udp socket bind ip: $ENV{TEST_NGINX_SERVER_IP}",
"udp bind address: $ENV{TEST_NGINX_SERVER_IP} while handling client connection, udp client: $ENV{TEST_NGINX_SERVER_IP}, server: 127.0.1.2:2986"]


=== TEST 3: upstream sockets bind not exist ip
--- stream_config
server {
   listen 127.0.1.2:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "udp bind address: " .. ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "$TEST_NGINX_NOT_EXIST_IP"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:bind(ip)
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end

      local ok, err = sock:setpeername("127.0.1.2", port)
      if not ok then
          ngx.log(ngx.INFO, err)
          return
      end

      local ok, err = sock:send("trigger")
      if not ok then
          ngx.log(ngx.ERR, err)
      end
}

--- error_log eval
["lua udp socket bind ip: $ENV{TEST_NGINX_NOT_EXIST_IP}",
"bind($ENV{TEST_NGINX_NOT_EXIST_IP}) failed"]
--- no_error_log
[error]


=== TEST 4: upstream sockets bind invalid ip
--- stream_config
server {
   listen 127.0.1.2:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "udp bind address from remote: " .. ngx.var.remote_addr)
     return
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "$TEST_NGINX_INVALID_IP"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:bind(ip)
      if not ok then
          ngx.log(ngx.INFO, err)
      end

      local ok, err = sock:setpeername("127.0.1.2", port)
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
["bad address while handling client connection, client: 127.0.0.1",
"udp bind address from remote: 127.0.0.1"]


=== TEST 5: upstream sockets bind 127.0.0.1 and resolve peername
--- SKIP
--- stream_config
lua_resolver $TEST_NGINX_LOCAL_DOMAIN_SERVER ipv6=off;
server {
   listen localhost:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "udp bind address: " .. ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "127.0.0.1"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:bind(ip)
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end

      local ok, err = sock:setpeername("localhost", port)
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
["lua udp socket bind ip: 127.0.0.1",
"udp bind address: 127.0.0.1 while handling client connection, udp client: 127.0.0.1, server: 127.0.0.1:2986"]


=== TEST 6: upstream sockets double bind 127.0.0.1 and resolve peername
--- SKIP
--- stream_config
lua_resolver $TEST_NGINX_LOCAL_DOMAIN_SERVER ipv6=off;
server {
   listen localhost:2986 udp;
   content_by_lua_block {
     ngx.log(ngx.INFO, "udp bind address: " .. ngx.var.remote_addr)
    }
}
--- stream_server_config
  content_by_lua_block {
      local ip = "127.0.0.1"
      local port = 2986
      local sock = ngx.socket.udp()

      local ok, err = sock:bind(ip)
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end

      local ok, err = sock:setpeername("localhost", port)
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end

      local ok, err = sock:bind("$TEST_NGINX_SERVER_IP")
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end

      local ok, err = sock:setpeername("localhost", port)
      if not ok then
          ngx.log(ngx.ERR, err)
          return
      end
}

--- no_error_log
[error]
