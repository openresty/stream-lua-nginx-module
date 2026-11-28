# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket::Lua::Stream;

repeat_each(1);
plan tests => 7;
no_shuffle();

my $old_umask = umask 0022;
add_cleanup_handler(sub { umask $old_umask; });

run_tests();

__DATA__

=== TEST 1: new SSL key log is owner-only
--- skip_openssl: 5: < 1.1.1
--- stream_server_config
    lua_ssl_key_log sslkey.log;

    return "ok\n";
--- init
my $key_log = server_root() . "/conf/sslkey.log";
my $mode = (stat $key_log)[2];
defined $mode or die "failed to stat $key_log: $!";
$mode &= 0777;
die sprintf("unexpected key log mode %04o", $mode) unless $mode == 0600;
--- stream_response
ok
--- no_error_log
[error]
[alert]
[emerg]



=== TEST 2: broad existing SSL key log permissions are rejected
--- skip_openssl: 2: < 1.1.1
--- stream_server_config
    lua_ssl_key_log ../html/sslkey.log;

    return "ok";
--- user_files
>>> sslkey.log
existing key log
--- must_die
--- error_log eval
qr/\[emerg\].*the SSL key log file ".*sslkey\.log" must have owner-only permissions/
