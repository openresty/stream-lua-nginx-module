# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua::Stream 'no_plan';

run_tests();

__DATA__

=== TEST 1: flag eq
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0, 1)
        local val = dogs:get("Bernese", 1)
        ngx.say(val, " ", type(val))
    }
--- stream_response
nil nil
--- no_error_log
[error]



=== TEST 2: fleq neq
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0, 1)
        local val = dogs:get("Bernese", 2)
        ngx.say(val, " " , type(val))
    }
--- stream_response
42 number
--- no_error_log
[error]



=== TEST 3: set with no flag
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0)
        local val = dogs:get("Bernese", 2)
        ngx.say(val, " " , type(val))
    }
--- stream_response
42 number
--- no_error_log
[error]



=== TEST 4: get with no flag
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0, 1)
        local val = dogs:get("Bernese")
        ngx.say(val, " " , type(val))
    }
--- stream_response
42 number
--- no_error_log
[error]



=== TEST 5: set and get with no flag
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0)
        local val = dogs:get("Bernese")
        ngx.say(val, " " , type(val))
    }
--- stream_response
42 number
--- no_error_log
[error]



=== TEST 6: set no flag, and read with 0 flag
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42)
        local val = dogs:get("Bernese", 0)
        ngx.say(val, " " , type(val))
    }
--- stream_response
nil nil
--- no_error_log
[error]


=== TEST 7: flags_match is true
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0, 1)
        local val, err, flags_match = dogs:get("Bernese", 1)

        ngx.say(val, " ", type(val), " : ",
                err, " ", type(err), " : ",
                flags_match, " ", type(flags_match))
    }
--- stream_response
nil nil : nil nil : true boolean
--- no_error_log
[error]



=== TEST 8: flags_match is nil
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        local val, err, flags_match = dogs:get("Bernese", 3)
        ngx.say(flags_match, " ", type(flags_match))
    }
--- stream_response
nil nil
--- no_error_log
[error]



=== TEST 9: get when flag is not number
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0, 1)
        local val = dogs:get("Bernese", {})
    }
--- error_log
cannot convert 'table' to 'int'


=== TEST 10: flag eq stale
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0.01, 1)
        ngx.sleep(0.02)
        local val = dogs:get_stale("Bernese", 1)
        ngx.say(val, " ", type(val))
    }
--- stream_response
nil nil
--- no_error_log
[error]



=== TEST 11: fleq neq stale
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0.01, 1)
        ngx.sleep(0.02)
        local val = dogs:get_stale("Bernese", 2)
        ngx.say(val, " " , type(val))
    }
--- stream_response
42 number
--- no_error_log
[error]



=== TEST 12: get_stale with no flag
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0.01, 1)
        ngx.sleep(0.02)
        local val = dogs:get_stale("Bernese")
        ngx.say(val, " " , type(val))
    }
--- stream_response
42 number
--- no_error_log
[error]



=== TEST 13: flags_match is true
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0.01, 1)
        ngx.sleep(0.02)
        local val, err, stale, flags_match = dogs:get_stale("Bernese", 1)

        ngx.say(val, " ", type(val), " : ",
                err, " ", type(err), " : ",
                flags_match, " ", type(flags_match))
    }
--- stream_response
nil nil : nil nil : true boolean
--- no_error_log
[error]



=== TEST 14: flags_match is nil
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        local val, err, stale, flags_match = dogs:get_stale("Bernese", 3)
        ngx.say(flags_match, " ", type(flags_match))
    }
--- stream_response
nil nil
--- no_error_log
[error]



=== TEST 15: get when flag is not number
--- stream_config
    lua_shared_dict dogs 1m;
--- stream_server_config
    content_by_lua_block {
        local dogs = ngx.shared.dogs
        dogs:set("Bernese", 42, 0, 1)
        local val = dogs:get_stale("Bernese", {})
    }
--- error_log
cannot convert 'table' to 'int'
