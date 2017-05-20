
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 */


#ifndef _NGX_STREAM_LUA_COMMON_H_INCLUDED_
#define _NGX_STREAM_LUA_COMMON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <nginx.h>

#include <setjmp.h>
#include <stdint.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>


#define ngx_stream_lua_probe_info(s)


#ifndef NGX_LUA_NO_FFI_API
#define NGX_STREAM_LUA_FFI_NO_REQ_CTX         -100
#define NGX_STREAM_LUA_FFI_BAD_CONTEXT        -101
#endif


#ifdef NGX_LUA_USE_ASSERT
#   include <assert.h>
#   define ngx_stream_lua_assert(a)  assert(a)
#else
#   define ngx_stream_lua_assert(a)
#endif


#ifndef NGX_HAVE_SHA1
#   if (nginx_version >= 1011002)
#       define NGX_HAVE_SHA1  1
#   endif
#endif


#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif


#ifndef NGX_STREAM_LUA_MAX_ARGS
#define NGX_STREAM_LUA_MAX_ARGS 100
#endif


/* must be within 16 bit */
#define NGX_STREAM_LUA_CONTEXT_CONTENT        0x001
#define NGX_STREAM_LUA_CONTEXT_LOG            0x002
#define NGX_STREAM_LUA_CONTEXT_TIMER          0x004
#define NGX_STREAM_LUA_CONTEXT_INIT_WORKER    0x008
#define NGX_STREAM_LUA_CONTEXT_BALANCER       0x010


/* Nginx Stream Lua Inline tag prefix */

#define NGX_STREAM_LUA_INLINE_TAG "nhli_"

#define NGX_STREAM_LUA_INLINE_TAG_LEN \
    (sizeof(NGX_STREAM_LUA_INLINE_TAG) - 1)

#define NGX_STREAM_LUA_INLINE_KEY_LEN \
    (NGX_STREAM_LUA_INLINE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)

/* Nginx Stream Lua File tag prefix */

#define NGX_STREAM_LUA_FILE_TAG "nhlf_"

#define NGX_STREAM_LUA_FILE_TAG_LEN \
    (sizeof(NGX_STREAM_LUA_FILE_TAG) - 1)

#define NGX_STREAM_LUA_FILE_KEY_LEN \
    (NGX_STREAM_LUA_FILE_TAG_LEN + 2 * MD5_DIGEST_LENGTH)

#define NGX_STREAM_CLIENT_CLOSED_REQUEST     499


typedef void (*ngx_stream_lua_cleanup_pt)(void *data);

typedef struct ngx_stream_lua_cleanup_s  ngx_stream_lua_cleanup_t;

struct ngx_stream_lua_cleanup_s {
    ngx_stream_lua_cleanup_pt               handler;
    void                                   *data;
    ngx_stream_lua_cleanup_t               *next;
};


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
#if (nginx_version >= 1009013)
    ngx_resolver_addr_t             *addrs;
#else
    ngx_addr_t                      *addrs;
#endif

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_stream_lua_resolved_t;


typedef struct ngx_stream_lua_semaphore_mm_s  ngx_stream_lua_semaphore_mm_t;
typedef struct ngx_stream_lua_main_conf_s  ngx_stream_lua_main_conf_t;
typedef struct ngx_stream_lua_srv_conf_s  ngx_stream_lua_srv_conf_t;


typedef struct ngx_stream_lua_balancer_peer_data_s
    ngx_stream_lua_balancer_peer_data_t;


typedef ngx_int_t (*ngx_stream_lua_main_conf_handler_pt)(ngx_log_t *log,
    ngx_stream_lua_main_conf_t *lmcf, lua_State *L);
typedef ngx_int_t (*ngx_stream_lua_srv_conf_handler_pt)(ngx_stream_session_t *s,
    ngx_stream_lua_srv_conf_t *lscf, lua_State *L);


typedef struct {
    u_char              *package;
    lua_CFunction        loader;
} ngx_stream_lua_preload_hook_t;


struct ngx_stream_lua_main_conf_s {
    lua_State           *lua;

    ngx_str_t            lua_path;
    ngx_str_t            lua_cpath;

    ngx_cycle_t         *cycle;
    ngx_pool_t          *pool;

    ngx_int_t            max_pending_timers;
    ngx_int_t            pending_timers;

    ngx_int_t            max_running_timers;
    ngx_int_t            running_timers;

    ngx_connection_t    *watcher;  /* for watching the process exit event */

#if (NGX_PCRE)
    ngx_int_t                            regex_cache_entries;
    ngx_int_t                            regex_cache_max_entries;
    ngx_int_t                            regex_match_limit;
#endif

    ngx_array_t                         *shm_zones;  /* of ngx_shm_zone_t* */

    ngx_array_t                         *preload_hooks;
                                        /* of ngx_stream_lua_preload_hook_t */

    ngx_stream_lua_main_conf_handler_pt  init_handler;
    ngx_str_t                            init_src;

    ngx_stream_lua_main_conf_handler_pt  init_worker_handler;
    ngx_str_t                            init_worker_src;

    ngx_stream_lua_balancer_peer_data_t     *balancer_peer_data;
                    /* balancer_by_lua does not support yielding and
                     * there cannot be any conflicts among concurrent requests,
                     * thus it is safe to store the peer data in the main conf.
                     */

    ngx_uint_t                           shm_zones_inited;

    ngx_stream_lua_semaphore_mm_t       *semaphore_mm;

    unsigned                             requires_access:1;
    unsigned                             requires_shm:1;
};


typedef struct ngx_stream_lua_ctx_s  ngx_stream_lua_ctx_t;


typedef ngx_int_t (*ngx_stream_lua_handler_pt)(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx);
typedef void (*ngx_stream_lua_event_handler_pt)(ngx_stream_session_t *s,
    ngx_stream_lua_ctx_t *ctx);


struct ngx_stream_lua_srv_conf_s {

#if (NGX_STREAM_SSL)
    ngx_ssl_t              *ssl;  /* shared by SSL cosockets */
    ngx_uint_t              ssl_protocols;
    ngx_str_t               ssl_ciphers;
    ngx_uint_t              ssl_verify_depth;
    ngx_str_t               ssl_trusted_certificate;
    ngx_str_t               ssl_crl;
#endif

    ngx_stream_lua_handler_pt           content_handler;

    u_char                             *content_chunkname;
    ngx_str_t                           content_src;    /*  content_by_lua
                                                         *  inline script/script
                                                         *  file path
                                                         */
    u_char                             *content_src_key; /* cached key for
                                                          * content_src
                                                          */

    ngx_flag_t                          enable_code_cache; /* whether to
                                                            * enable
                                                            * code cache */

    ngx_flag_t                          check_client_abort;

    ngx_msec_t                          resolver_timeout; /* resolver_timeout */
    ngx_resolver_t                     *resolver;         /* resolver */

    ngx_msec_t                          keepalive_timeout;
    ngx_msec_t                          connect_timeout;
    ngx_msec_t                          send_timeout;
    ngx_msec_t                          read_timeout;

    size_t                              send_lowat;
    size_t                              buffer_size;

    ngx_uint_t                          pool_size;

    ngx_flag_t                          log_socket_errors;

    ngx_uint_t                          lingering_close;
    ngx_msec_t                          lingering_time;
    ngx_msec_t                          lingering_timeout;

    struct {
        ngx_str_t    src;
        u_char      *src_key;

        ngx_stream_lua_srv_conf_handler_pt  handler;
    } balancer;
};


enum {
    NGX_STREAM_LUA_LINGERING_OFF = 0,
    NGX_STREAM_LUA_LINGERING_ON,
    NGX_STREAM_LUA_LINGERING_ALWAYS
};


typedef enum {
    NGX_STREAM_LUA_USER_CORO_NOP      = 0,
    NGX_STREAM_LUA_USER_CORO_RESUME   = 1,
    NGX_STREAM_LUA_USER_CORO_YIELD    = 2,
    NGX_STREAM_LUA_USER_THREAD_RESUME = 3
} ngx_stream_lua_user_coro_op_t;


typedef enum {
    NGX_STREAM_LUA_CO_RUNNING   = 0, /* coroutine running */
    NGX_STREAM_LUA_CO_SUSPENDED = 1, /* coroutine suspended */
    NGX_STREAM_LUA_CO_NORMAL    = 2, /* coroutine normal */
    NGX_STREAM_LUA_CO_DEAD      = 3, /* coroutine dead */
    NGX_STREAM_LUA_CO_ZOMBIE    = 4, /* coroutine zombie */
} ngx_stream_lua_co_status_t;


typedef struct ngx_stream_lua_co_ctx_s  ngx_stream_lua_co_ctx_t;
typedef void (*ngx_stream_lua_co_cleanup_pt)(ngx_stream_lua_co_ctx_t *coctx);
typedef struct ngx_stream_lua_posted_thread_s  ngx_stream_lua_posted_thread_t;


struct ngx_stream_lua_posted_thread_s {
    ngx_stream_lua_co_ctx_t               *co_ctx;
    ngx_stream_lua_posted_thread_t        *next;
};


struct ngx_stream_lua_co_ctx_s {
    void                            *data;      /* user state for cosockets */

    lua_State                       *co;
    ngx_stream_lua_co_ctx_t         *parent_co_ctx;

    ngx_stream_lua_posted_thread_t  *zombie_child_threads;

    ngx_stream_lua_co_cleanup_pt     cleanup;

    ngx_event_t                      sleep;  /* used for ngx.sleep */

    ngx_queue_t                      sem_wait_queue;

#ifdef NGX_LUA_USE_ASSERT
    int                              co_top; /* stack top after
                                              * yielding/creation,
                                              * only for sanity checks */
#endif

    int                              co_ref; /* reference to anchor the thread
                                              * coroutines (entry coroutine
                                              * and user threads) in the Lua
                                              * registry, preventing the
                                              * thread coroutine from beging
                                              * collected by the Lua GC */

    unsigned                         waited_by_parent:1;  /* whether being
                                                           * waited by a
                                                           * parent coroutine
                                                           */

    unsigned                         co_status:3;  /* the current coroutine's
                                                    * status */

    unsigned                         is_uthread:1; /* whether the current
                                                    * coroutine is a user
                                                    * thread */

    unsigned                         thread_spawn_yielded:1;
                                                    /* yielded from the
                                                     * ngx.thread.spawn()
                                                     * call */

    unsigned                         sem_resume_status:1;
    unsigned                         flushing:1;
};


typedef struct {
    lua_State       *vm;
    ngx_int_t        count;
} ngx_stream_lua_vm_state_t;


struct ngx_stream_lua_ctx_s {
    ngx_stream_lua_event_handler_pt       read_event_handler;
    ngx_stream_lua_event_handler_pt       write_event_handler;

    ngx_chain_writer_ctx_t                out_writer;

    /* for lua_coce_cache off: */
    ngx_stream_lua_vm_state_t *vm_state;
    ngx_stream_lua_handler_pt  resume_handler;
    ngx_stream_session_t      *session;

    ngx_stream_lua_co_ctx_t   *cur_co_ctx; /* co ctx for the current
                                            * coroutine */

    /* FIXME: we should use rbtree here to prevent O(n) lookup overhead */
    ngx_list_t                *user_co_ctx; /* coroutine contexts for user
                                             * coroutines */

    ngx_stream_lua_co_ctx_t    entry_co_ctx; /* coroutine context for the
                                              * entry coroutine */

    ngx_stream_lua_co_ctx_t   *on_abort_co_ctx; /* coroutine context for the
                                                 * on_abort thread */

    ngx_chain_t               *free_bufs;
    ngx_chain_t               *downstream_busy_bufs;
    ngx_chain_t               *upstream_busy_bufs;
    ngx_chain_t               *free_recv_bufs;

    ngx_stream_lua_cleanup_t  *cleanup;

    ngx_stream_lua_cleanup_t  *free_cleanup; /* free list of cleanup records */

    ngx_int_t                  exit_code;

    void                      *downstream;
                                       /* can be either
                                        * ngx_stream_lua_socket_tcp_upstream_t
                                        * or ngx_stream_lua_co_ctx_t */

    ngx_stream_lua_posted_thread_t   *posted_threads;

    time_t                     lingering_time;

    unsigned                   flushing_coros; /* number of coroutines waiting
                                                * on ngx.flush() */

    int                        uthreads; /* number of active user threads */

    int                        ctx_ref;  /* reference to anchor
                                          * request ctx data in lua
                                          * registry */

    uint16_t                   context;   /* the current running directive
                                           * context (or running phase) for
                                           * the current Lua chunk */

    unsigned                   co_op:2; /*  coroutine API operation */

    unsigned                   lingering_close:1;
    unsigned                   exited:1;

    unsigned                   entered_content_phase:1;
    unsigned                   writing_raw_req_socket:1; /* used by raw
                                                          * downstream
                                                          * socket */

    unsigned                   acquired_raw_req_socket:1;
                                                /* whether a raw req socket
                                                 * is acquired */

    unsigned                   no_abort:1; /* prohibit "world abortion" via
                                            * ngx.exit()
                                            * and etc */

    unsigned                   done:1;  /* session being finalized */
    unsigned                   eof:1;
};


extern ngx_module_t ngx_stream_lua_module;


#endif /* _NGX_STREAM_LUA_COMMON_H_INCLUDED_ */
