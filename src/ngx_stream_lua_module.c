
/*
 * Copyright (C) Yichun Zhang (agentzh)
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 */


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_stream_lua_common.h"
#include "ngx_stream_lua_directive.h"
#include "ngx_stream_lua_contentby.h"
#include "ngx_stream_lua_balancer.h"
#include "ngx_stream_lua_semaphore.h"
#include "ngx_stream_lua_initby.h"
#include "ngx_stream_lua_initworkerby.h"
#include "ngx_stream_lua_util.h"


static void *ngx_stream_lua_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_lua_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_lua_lowat_check(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_stream_lua_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_stream_lua_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_stream_lua_init(ngx_conf_t *cf);
#if (NGX_STREAM_SSL)
static ngx_int_t ngx_stream_lua_set_ssl(ngx_conf_t *cf,
    ngx_stream_lua_srv_conf_t *lscf);
#endif


static ngx_conf_post_t  ngx_stream_lua_lowat_post =
    { ngx_stream_lua_lowat_check };


static ngx_conf_enum_t  ngx_stream_lua_lingering_close[] = {
    { ngx_string("off"), NGX_STREAM_LUA_LINGERING_OFF },
    { ngx_string("on"), NGX_STREAM_LUA_LINGERING_ON },
    { ngx_string("always"), NGX_STREAM_LUA_LINGERING_ALWAYS },
    { ngx_null_string, 0 }
};


#if (NGX_STREAM_SSL)

static ngx_conf_bitmask_t  ngx_stream_lua_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_null_string, 0 }
};

#endif


static ngx_command_t  ngx_stream_lua_commands[] = {

    { ngx_string("init_by_lua_block"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_lua_init_by_lua_block,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) ngx_stream_lua_init_by_inline },

    { ngx_string("init_by_lua_file"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_stream_lua_init_by_lua,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) ngx_stream_lua_init_by_file },

    { ngx_string("init_worker_by_lua_block"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_lua_init_worker_by_lua_block,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) ngx_stream_lua_init_worker_by_inline },

    { ngx_string("init_worker_by_lua_file"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_stream_lua_init_worker_by_lua,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      (void *) ngx_stream_lua_init_worker_by_file },

    { ngx_string("content_by_lua_block"),
      NGX_STREAM_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_lua_content_by_lua_block,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) ngx_stream_lua_content_handler_inline },

    { ngx_string("content_by_lua_file"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_lua_content_by_lua,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) ngx_stream_lua_content_handler_file },

    { ngx_string("balancer_by_lua_block"),
      NGX_STREAM_UPS_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_lua_balancer_by_lua_block,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) ngx_stream_lua_balancer_handler_inline },

    { ngx_string("balancer_by_lua_file"),
      NGX_STREAM_UPS_CONF|NGX_CONF_TAKE1,
      ngx_stream_lua_balancer_by_lua,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      (void *) ngx_stream_lua_balancer_handler_file },

    { ngx_string("lua_max_running_timers"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_lua_main_conf_t, max_running_timers),
      NULL },

    { ngx_string("lua_max_pending_timers"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_lua_main_conf_t, max_pending_timers),
      NULL },

    { ngx_string("lua_shared_dict"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_stream_lua_shared_dict,
      0,
      0,
      NULL },

#if (NGX_PCRE)
    { ngx_string("lua_regex_cache_max_entries"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_lua_main_conf_t, regex_cache_max_entries),
      NULL },

    { ngx_string("lua_regex_match_limit"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_MAIN_CONF_OFFSET,
      offsetof(ngx_stream_lua_main_conf_t, regex_match_limit),
      NULL },
#endif

    { ngx_string("lua_resolver"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_lua_resolver,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua_resolver_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, resolver_timeout),
      NULL },

    { ngx_string("lua_socket_keepalive_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, keepalive_timeout),
      NULL },

    { ngx_string("lua_socket_connect_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("lua_socket_send_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, send_timeout),
      NULL },

    { ngx_string("lua_socket_send_lowat"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, send_lowat),
      &ngx_stream_lua_lowat_post },

    { ngx_string("lua_socket_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("lua_socket_pool_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, pool_size),
      NULL },

    { ngx_string("lua_socket_read_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, read_timeout),
      NULL },

     { ngx_string("lua_socket_log_errors"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, log_socket_errors),
      NULL },

    { ngx_string("lua_check_client_abort"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, check_client_abort),
      NULL },

    { ngx_string("lua_code_cache"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_lua_code_cache,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, enable_code_cache),
      NULL },

    { ngx_string("lua_package_cpath"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_stream_lua_package_cpath,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua_package_path"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_stream_lua_package_path,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua_lingering_close"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, lingering_close),
      &ngx_stream_lua_lingering_close },

    { ngx_string("lua_lingering_time"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, lingering_time),
      NULL },

    { ngx_string("lua_lingering_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, lingering_timeout),
      NULL },

#if (NGX_STREAM_SSL)

    { ngx_string("lua_ssl_protocols"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, ssl_protocols),
      &ngx_stream_lua_ssl_protocols },

    { ngx_string("lua_ssl_ciphers"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, ssl_ciphers),
      NULL },

    { ngx_string("lua_ssl_verify_depth"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, ssl_verify_depth),
      NULL },

    { ngx_string("lua_ssl_trusted_certificate"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, ssl_trusted_certificate),
      NULL },

    { ngx_string("lua_ssl_crl"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_lua_srv_conf_t, ssl_crl),
      NULL },

#endif  /* NGX_STREAM_SSL */

      ngx_null_command
};


static ngx_stream_module_t  ngx_stream_lua_module_ctx = {
#if (nginx_version >= 1011002)
    NULL,                                  /* preconfiguration */
#endif
    ngx_stream_lua_init,                   /* postconfiguration */

    ngx_stream_lua_create_main_conf,       /* create main configuration */
    ngx_stream_lua_init_main_conf,         /* init main configuration */

    ngx_stream_lua_create_srv_conf,        /* create server configuration */
    ngx_stream_lua_merge_srv_conf          /* merge server configuration */
};


ngx_module_t  ngx_stream_lua_module = {
    NGX_MODULE_V1,
    &ngx_stream_lua_module_ctx,            /* module context */
    ngx_stream_lua_commands,               /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_stream_lua_init_worker,            /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};



static void *
ngx_stream_lua_create_main_conf(ngx_conf_t *cf)
{
    ngx_stream_lua_main_conf_t    *lmcf;
    ngx_stream_lua_semaphore_mm_t *mm;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_lua_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    /* set by ngx_pcalloc:
     *      lmcf->lua = NULL;
     *      lmcf->lua_path = { 0, NULL };
     *      lmcf->lua_cpath = { 0, NULL };
     *      lmcf->pending_timers = 0;
     *      lmcf->running_timers = 0;
     *      lmcf->watcher = NULL;
     *      lmcf->regex_cache_entries = 0;
     *      lmcf->shm_zones = NULL;
     *      lmcf->init_handler = NULL;
     *      lmcf->init_src = { 0, NULL };
     *      lmcf->shm_zones_inited = 0;
     *      lmcf->preload_hooks = NULL;
     *      lmcf->requires_rewrite = 0;
     *      lmcf->requires_access = 0;
     *      lmcf->requires_log = 0;
     *      lmcf->requires_shm = 0;
     */

    lmcf->pool = cf->pool;
    lmcf->max_pending_timers = NGX_CONF_UNSET;
    lmcf->max_running_timers = NGX_CONF_UNSET;
#if (NGX_PCRE)
    lmcf->regex_cache_max_entries = NGX_CONF_UNSET;
    lmcf->regex_match_limit = NGX_CONF_UNSET;
#endif

    mm = ngx_palloc(cf->pool, sizeof(ngx_stream_lua_semaphore_mm_t));
    if (mm == NULL) {
        return NULL;
    }

    lmcf->semaphore_mm = mm;
    mm->lmcf = lmcf;

    ngx_queue_init(&mm->free_queue);
    mm->cur_epoch = 0;
    mm->total = 0;
    mm->used = 0;

    /* it's better to be 4096, but it needs some space for
     * ngx_stream_lua_semaphore_mm_block_t, one is enough, so it is 4095
     */
    mm->num_per_block = 4095;

    dd("nginx Lua module main config structure initialized!");

    return lmcf;
}


static char *
ngx_stream_lua_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_stream_lua_main_conf_t *lmcf = conf;

#if (NGX_PCRE)
    if (lmcf->regex_cache_max_entries == NGX_CONF_UNSET) {
        lmcf->regex_cache_max_entries = 1024;
    }

    if (lmcf->regex_match_limit == NGX_CONF_UNSET) {
        lmcf->regex_match_limit = 0;
    }
#endif

    if (lmcf->max_pending_timers == NGX_CONF_UNSET) {
        lmcf->max_pending_timers = 1024;
    }

    if (lmcf->max_running_timers == NGX_CONF_UNSET) {
        lmcf->max_running_timers = 256;
    }

    lmcf->cycle = cf->cycle;

    return NGX_CONF_OK;
}


static void *
ngx_stream_lua_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_lua_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_lua_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *      conf->content_src = { {0, NULL}, {0, NULL}, 0 };
     *      conf->content_src_key = NULL
     *      conf->content_handler = NULL;
     *      conf->content_chunkname = NULL;
     *
     *      conf->ssl = 0;
     *      conf->ssl_protocols = 0;
     *      conf->ssl_ciphers = { 0, NULL };
     *      conf->ssl_trusted_certificate = { 0, NULL };
     *      conf->ssl_crl = { 0, NULL };
     */

    conf->enable_code_cache  = NGX_CONF_UNSET;
    conf->check_client_abort = NGX_CONF_UNSET;

    conf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    conf->keepalive_timeout = NGX_CONF_UNSET_MSEC;
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_timeout = NGX_CONF_UNSET_MSEC;
    conf->read_timeout = NGX_CONF_UNSET_MSEC;
    conf->send_lowat = NGX_CONF_UNSET_SIZE;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->pool_size = NGX_CONF_UNSET_UINT;

    conf->log_socket_errors = NGX_CONF_UNSET;

    conf->lingering_close = NGX_CONF_UNSET_UINT;
    conf->lingering_time = NGX_CONF_UNSET_MSEC;
    conf->lingering_timeout = NGX_CONF_UNSET_MSEC;

#if (NGX_STREAM_SSL)
    conf->ssl_verify_depth = NGX_CONF_UNSET_UINT;
#endif

    return conf;
}


static char *
ngx_stream_lua_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_lua_srv_conf_t *prev = parent;
    ngx_stream_lua_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in stream {} context
             * to inherit it in all servers
             */

            prev->resolver = ngx_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    ngx_conf_merge_value(conf->enable_code_cache, prev->enable_code_cache, 1);
    ngx_conf_merge_value(conf->check_client_abort, prev->check_client_abort, 0);

    ngx_conf_merge_msec_value(conf->keepalive_timeout,
                              prev->keepalive_timeout, 60000);

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->send_timeout,
                              prev->send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->read_timeout,
                              prev->read_timeout, 60000);

    ngx_conf_merge_size_value(conf->send_lowat,
                              prev->send_lowat, 0);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_uint_value(conf->pool_size, prev->pool_size, 30);

    ngx_conf_merge_value(conf->log_socket_errors, prev->log_socket_errors, 1);

    ngx_conf_merge_uint_value(conf->lingering_close,
                              prev->lingering_close,
                              NGX_STREAM_LUA_LINGERING_ON);
    ngx_conf_merge_msec_value(conf->lingering_time,
                              prev->lingering_time, 30000);
    ngx_conf_merge_msec_value(conf->lingering_timeout,
                              prev->lingering_timeout, 5000);


#if (NGX_STREAM_SSL)

    ngx_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                                 (NGX_CONF_BITMASK_SET|NGX_SSL_SSLv3
                                  |NGX_SSL_TLSv1|NGX_SSL_TLSv1_1
                                  |NGX_SSL_TLSv1_2));

    ngx_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    ngx_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    ngx_conf_merge_str_value(conf->ssl_trusted_certificate,
                             prev->ssl_trusted_certificate, "");
    ngx_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    if (ngx_stream_lua_set_ssl(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#endif

    return NGX_CONF_OK;
}


static char *
ngx_stream_lua_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"lua_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"lua_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_stream_lua_init(ngx_conf_t *cf)
{
    ngx_int_t                   rc;
    volatile ngx_cycle_t       *saved_cycle;
    ngx_stream_lua_main_conf_t *lmcf;
#ifndef NGX_LUA_NO_FFI_API
    ngx_pool_cleanup_t         *cln;
#endif

    lmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_lua_module);

#ifndef NGX_LUA_NO_FFI_API

    /* add the cleanup of semaphores after the lua_close */
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->data = lmcf;
    cln->handler = ngx_stream_lua_cleanup_semaphore_mm;

#endif

    if (lmcf->lua == NULL) {
        dd("initializing lua vm");

        lmcf->lua = ngx_stream_lua_init_vm(NULL, cf->cycle, cf->pool, lmcf,
                                           cf->log, NULL);
        if (lmcf->lua == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                               "failed to initialize Lua VM");
            return NGX_ERROR;
        }

        if (!lmcf->requires_shm && lmcf->init_handler) {
            saved_cycle = ngx_cycle;
            ngx_cycle = cf->cycle;

            rc = lmcf->init_handler(cf->log, lmcf, lmcf->lua);

            ngx_cycle = saved_cycle;

            if (rc != NGX_OK) {
                /* an error happened */
                return NGX_ERROR;
            }
        }

        dd("Lua VM initialized!");
    }

    return NGX_OK;
}


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_lua_set_ssl(ngx_conf_t *cf, ngx_stream_lua_srv_conf_t *lscf)
{
    ngx_pool_cleanup_t  *cln;

    lscf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (lscf->ssl == NULL) {
        return NGX_ERROR;
    }

    lscf->ssl->log = cf->log;

    if (ngx_ssl_create(lscf->ssl, lscf->ssl_protocols, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = lscf->ssl;

    if (SSL_CTX_set_cipher_list(lscf->ssl->ctx,
                                (const char *) lscf->ssl_ciphers.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      &lscf->ssl_ciphers);
        return NGX_ERROR;
    }

    if (lscf->ssl_trusted_certificate.len) {

#if defined(nginx_version) && nginx_version >= 1003007

        if (ngx_ssl_trusted_certificate(cf, lscf->ssl,
                                        &lscf->ssl_trusted_certificate,
                                        lscf->ssl_verify_depth)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

#else

        ngx_log_error(NGX_LOG_CRIT, cf->log, 0, "at least nginx 1.3.7 is "
                      "required for the \"lua_ssl_trusted_certificate\" "
                      "directive");
        return NGX_ERROR;

#endif
    }

    dd("ssl crl: %.*s", (int) lscf->ssl_crl.len, lscf->ssl_crl.data);

    if (ngx_ssl_crl(cf, lscf->ssl, &lscf->ssl_crl) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

#endif  /* NGX_STREAM_SSL */
