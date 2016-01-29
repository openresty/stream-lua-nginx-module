#!/usr/bin/env perl

use strict;
use warnings;

my ($port_var, $section, $tokens_stmt, $seen_closing, $uri);
while (<>) {
    if (/^--- (\w+)/) {
        $section = $1;
        undef $port_var;
        undef $tokens_stmt;
        undef $seen_closing;
        undef $seen_closing;
        undef $uri;
        print;
        next;
    }
    if (/^\s*set \$port (\$TEST_NGINX_\w+);/) {
        $port_var = $1;
        next;
    }
    if (defined $section && $section eq 'stream_server_config') {
        if (/^\s*server_tokens .*/) {
            $tokens_stmt = $_;
            next;
        }
        if (/^\s*lua_socket_buffer_size/) {
            s/^\s*/    /;
            print;
            next;
        }
        if (/^(\s*)local port = ngx\.var\.port$/) {
            if (!defined $port_var) {
                die "No port variable defined";
            }
            print "${1}local port = $port_var\n";
            next;
        }
        if (!$uri && m{\bGET (/\S+) }) {
            $uri = $1;
        }
        if (!$seen_closing && /^    \}/) {
            $seen_closing = 1;
            print;
            print "\n--- config\n";
            if (defined $tokens_stmt) {
                print $tokens_stmt;
            }
            if (!defined $uri) {
                die "No uri found";
            }
            print "    location = $uri {";
            next;
        }
    }

    print;
}
