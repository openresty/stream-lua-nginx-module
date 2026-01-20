/*
 * Copyright (C) Yichun Zhang (agentzh)
 */

#ifndef DDEBUG
#define DDEBUG 0
#endif

#include "ddebug.h"
#include "ngx_stream_lua_proxy_ssl_certby.h"

#ifdef HAVE_LUA_PROXY_SSL
#include "ngx_stream_lua_cache.h"
#include "ngx_stream_lua_initworkerby.h"
#include "ngx_stream_lua_util.h"
#include "ngx_stream_ssl_module.h"
#include "ngx_stream_lua_contentby.h"
#include "ngx_stream_lua_directive.h"
#include "ngx_stream_lua_ssl.h"


static void ngx_stream_lua_proxy_ssl_cert_done(void *data);
static void ngx_stream_lua_proxy_ssl_cert_aborted(void *data);
static ngx_int_t ngx_stream_lua_proxy_ssl_cert_by_chunk(lua_State *L,
    ngx_stream_lua_request_t *r);


ngx_int_t
ngx_stream_lua_proxy_ssl_cert_set_callback(ngx_conf_t *cf)
{
    ngx_flag_t           proxy_ssl = 0;
    ngx_pool_cleanup_t  *cln;
    ngx_ssl_t           *ssl;
    void                *pscf;

    /*
     * Nginx doesn't export ngx_stream_proxy_srv_conf_t, so we can't directly
     * get pscf here, and we also don't want to change ngx_stream_proxy_module's
     * code organization, since that it means to add a header file to Nginx.
     * I know it's a bit clumsy here, anyway the solution is good enough
     */
    for (cln = cf->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler != ngx_ssl_cleanup_ctx) {
            continue;
        }

        ssl = cln->data;

        pscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_proxy_module);
        if (pscf == ngx_ssl_get_server_conf(ssl->ctx)) {
            /* here we make sure that ssl is pscf->ssl */
            proxy_ssl = 1;

            break;
        }
    }

    if (!proxy_ssl) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "proxy_ssl_certificate_by_lua* should be used with "
                      "proxy_ssl directive");

        return NGX_ERROR;
    }

    SSL_CTX_set_cert_cb(ssl->ctx, ngx_stream_lua_proxy_ssl_cert_handler, NULL);

    return NGX_OK;
}


ngx_int_t
ngx_stream_lua_proxy_ssl_cert_handler_file(ngx_stream_lua_request_t *r,
    ngx_stream_lua_srv_conf_t *lscf, lua_State *L)
{
    ngx_int_t           rc;

    rc = ngx_stream_lua_cache_loadfile(r->connection->log, L,
                                       lscf->ups.proxy_ssl_cert_src.data,
                                       lscf->ups.proxy_ssl_cert_src_key);
    if (rc != NGX_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    ngx_stream_lua_assert(lua_isfunction(L, -1));

    return ngx_stream_lua_proxy_ssl_cert_by_chunk(L, r);
}


ngx_int_t
ngx_stream_lua_proxy_ssl_cert_handler_inline(ngx_stream_lua_request_t *r,
    ngx_stream_lua_srv_conf_t *lscf, lua_State *L)
{
    ngx_int_t           rc;

    rc = ngx_stream_lua_cache_loadbuffer(r->connection->log, L,
                                         lscf->ups.proxy_ssl_cert_src.data,
                                         lscf->ups.proxy_ssl_cert_src.len,
                                         lscf->ups.proxy_ssl_cert_src_key,
                                         "=proxy_ssl_certificate_by_lua");
    if (rc != NGX_OK) {
        return rc;
    }

    /*  make sure we have a valid code chunk */
    ngx_stream_lua_assert(lua_isfunction(L, -1));

    return ngx_stream_lua_proxy_ssl_cert_by_chunk(L, r);
}


char *
ngx_stream_lua_proxy_ssl_cert_by_lua_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char        *rv;
    ngx_conf_t   save;

    save = *cf;
    cf->handler = ngx_stream_lua_proxy_ssl_cert_by_lua;
    cf->handler_conf = conf;

    rv = ngx_stream_lua_conf_lua_block_parse(cf, cmd);

    *cf = save;

    return rv;
}


char *
ngx_stream_lua_proxy_ssl_cert_by_lua(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    u_char                           *p;
    u_char                           *name;
    ngx_str_t                        *value;
    ngx_stream_lua_srv_conf_t        *lscf = conf;

    /*  must specify a concrete handler */
    if (cmd->post == NULL) {
        return NGX_CONF_ERROR;
    }

    if (lscf->ups.proxy_ssl_cert_handler) {
        return "is duplicate";
    }

    if (ngx_stream_lua_ssl_init(cf->log) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    lscf->ups.proxy_ssl_cert_handler =
        (ngx_stream_lua_srv_conf_handler_pt) cmd->post;

    if (cmd->post == ngx_stream_lua_proxy_ssl_cert_handler_file) {
        /* Lua code in an external file */

        name = ngx_stream_lua_rebase_path(cf->pool, value[1].data,
                                          value[1].len);
        if (name == NULL) {
            return NGX_CONF_ERROR;
        }

        lscf->ups.proxy_ssl_cert_src.data = name;
        lscf->ups.proxy_ssl_cert_src.len = ngx_strlen(name);

        p = ngx_palloc(cf->pool, NGX_STREAM_LUA_FILE_KEY_LEN + 1);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        lscf->ups.proxy_ssl_cert_src_key = p;

        p = ngx_copy(p, NGX_STREAM_LUA_FILE_TAG, NGX_STREAM_LUA_FILE_TAG_LEN);
        p = ngx_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';

    } else {
        /* inlined Lua code */

        lscf->ups.proxy_ssl_cert_src = value[1];

        p = ngx_palloc(cf->pool,
                       sizeof("proxy_ssl_certificate_by_lua") +
                       NGX_STREAM_LUA_INLINE_KEY_LEN);
        if (p == NULL) {
            return NGX_CONF_ERROR;
        }

        lscf->ups.proxy_ssl_cert_src_key = p;

        p = ngx_copy(p, "proxy_ssl_certificate_by_lua",
                     sizeof("proxy_ssl_certificate_by_lua") - 1);
        p = ngx_copy(p, NGX_STREAM_LUA_INLINE_TAG,
                     NGX_STREAM_LUA_INLINE_TAG_LEN);
        p = ngx_stream_lua_digest_hex(p, value[1].data, value[1].len);
        *p = '\0';
    }

    return NGX_CONF_OK;
}


int
ngx_stream_lua_proxy_ssl_cert_handler(ngx_ssl_conn_t *ssl_conn, void *data)
{
    lua_State                          *L;
    ngx_int_t                           rc;
    ngx_connection_t                   *c;
    ngx_stream_lua_request_t           *r = NULL;
    ngx_pool_cleanup_t                 *cln;
    ngx_stream_lua_srv_conf_t          *lscf;
    ngx_stream_lua_ssl_ctx_t           *cctx;
    ngx_stream_session_t               *s;

    c = ngx_ssl_get_connection(ssl_conn);  /* upstream connection */

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "proxy ssl cert: connection reusable: %ud", c->reusable);

    cctx = ngx_stream_lua_ssl_get_ctx(c->ssl->connection);

    dd("proxy ssl cert handler, cert-ctx=%p", cctx);

    if (cctx && cctx->entered_proxy_ssl_cert_handler) {
        /* not the first time */

        if (cctx->done) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "proxy_ssl_certificate_by_lua: "
                           "cert cb exit code: %d",
                           cctx->exit_code);

            dd("lua proxy ssl cert done, finally");
            return cctx->exit_code;
        }

        return -1;
    }

    dd("first time");

    ngx_reusable_connection(c, 0);

    s = c->data;

    r = ngx_stream_lua_create_fake_request(s);
    if (r == NULL) {
        goto failed;
    }

    if (cctx == NULL) {
        cctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_lua_ssl_ctx_t));
        if (cctx == NULL) {
            goto failed;  /* error */
        }

        cctx->ctx_ref = LUA_NOREF;
    }

    cctx->connection = c;
    cctx->request = r;
    cctx->exit_code = 1;  /* successful by default */
    cctx->done = 0;
    cctx->entered_proxy_ssl_cert_handler = 1;
    cctx->pool = ngx_create_pool(128, c->log);
    if (cctx->pool == NULL) {
        goto failed;
    }

    dd("setting cctx");

    if (SSL_set_ex_data(c->ssl->connection, ngx_stream_lua_ssl_ctx_index,
                        cctx) == 0)
    {
        ngx_ssl_error(NGX_LOG_ALERT, c->log, 0, "SSL_set_ex_data() failed");
        goto failed;
    }

    lscf = ngx_stream_lua_get_module_srv_conf(r, ngx_stream_lua_module);

    /* TODO honor lua_code_cache off */
    L = ngx_stream_lua_get_lua_vm(r, NULL);

    c->log->action = "loading proxy ssl certificate by lua";

    rc = lscf->ups.proxy_ssl_cert_handler(r, lscf, L);

    if (rc >= NGX_OK || rc == NGX_ERROR) {
        cctx->done = 1;

        if (cctx->cleanup) {
            *cctx->cleanup = NULL;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "proxy_ssl_certificate_by_lua: "
                       "handler return value: %i, cert cb exit code: %d",
                       rc, cctx->exit_code);

        c->log->action = "proxy pass SSL handshaking";
        return cctx->exit_code;
    }

    /* rc == NGX_DONE */

    cln = ngx_pool_cleanup_add(cctx->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->handler = ngx_stream_lua_proxy_ssl_cert_done;
    cln->data = cctx;

    if (cctx->cleanup == NULL) {
        cln = ngx_pool_cleanup_add(c->pool, 0);
        if (cln == NULL) {
            goto failed;
        }

        cln->data = cctx;
        cctx->cleanup = &cln->handler;
    }

    *cctx->cleanup = ngx_stream_lua_proxy_ssl_cert_aborted;

    return -1;

#if 1
failed:

    if (cctx && cctx->pool) {
        ngx_destroy_pool(cctx->pool);
    }

    return 0;  /* failure or error */
#endif
}


static void
ngx_stream_lua_proxy_ssl_cert_done(void *data)
{
    ngx_connection_t          *c;
    ngx_stream_lua_ssl_ctx_t  *cctx = data;

    dd("lua proxy ssl cert done");

    if (cctx->aborted) {
        return;
    }

    ngx_stream_lua_assert(cctx->done == 0);

    cctx->done = 1;

    if (cctx->cleanup) {
        *cctx->cleanup = NULL;
    }

    c = cctx->connection;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->log->action = "proxy pass SSL handshaking";

    ngx_post_event(c->write, &ngx_posted_events);
}


static void
ngx_stream_lua_proxy_ssl_cert_aborted(void *data)
{
    ngx_stream_lua_ssl_ctx_t  *cctx = data;

    dd("lua proxy ssl cert aborted");

    if (cctx->done) {
        /* completed successfully already */
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, cctx->connection->log, 0,
                   "proxy_ssl_certificate_by_lua: cert cb aborted");

    cctx->aborted = 1;
    cctx->connection->ssl = NULL;
    cctx->exit_code = 0;
    if (cctx->pool) {
        ngx_destroy_pool(cctx->pool);
        cctx->pool = NULL;
    }
}


static ngx_int_t
ngx_stream_lua_proxy_ssl_cert_by_chunk(lua_State *L,
    ngx_stream_lua_request_t *r)
{
    int                              co_ref;
    ngx_int_t                        rc;
    lua_State                       *co;
    ngx_stream_lua_ctx_t            *ctx;
    ngx_pool_cleanup_t              *cln;
    ngx_stream_upstream_t           *u;
    ngx_connection_t                *c;
    ngx_stream_lua_ssl_ctx_t        *cctx;

    ctx = ngx_stream_lua_get_module_ctx(r, ngx_stream_lua_module);

    if (ctx == NULL) {
        ctx = ngx_stream_lua_create_ctx(r->session);
        if (ctx == NULL) {
            rc = NGX_ERROR;
            ngx_stream_lua_finalize_request(r, rc);
            return rc;
        }

    } else {
        dd("reset ctx");
        ngx_stream_lua_reset_ctx(r, L, ctx);
    }

    ctx->entered_content_phase = 1;

    /*  {{{ new coroutine to handle request */
    co = ngx_stream_lua_new_thread(r, L, &co_ref);

    if (co == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "stream failed to create new"
                      " coroutine to handle request");

        rc = NGX_ERROR;
        ngx_stream_lua_finalize_request(r, rc);
        return rc;
    }

    /*  move code closure to new coroutine */
    lua_xmove(L, co, 1);

#ifndef OPENRESTY_LUAJIT
    /*  set closure's env table to new coroutine's globals table */
    ngx_stream_lua_get_globals_table(co);
    lua_setfenv(co, -2);
#endif

    /* save nginx request in coroutine globals table */
    ngx_stream_lua_set_req(co, r);

    ctx->cur_co_ctx = &ctx->entry_co_ctx;
    ctx->cur_co_ctx->co = co;
    ctx->cur_co_ctx->co_ref = co_ref;
#ifdef NGX_LUA_USE_ASSERT
    ctx->cur_co_ctx->co_top = 1;
#endif

    ngx_stream_lua_attach_co_ctx_to_L(co, ctx->cur_co_ctx);

    /* register request cleanup hooks */
    if (ctx->cleanup == NULL) {
        u = r->session->upstream;
        c = u->peer.connection;
        cctx = ngx_stream_lua_ssl_get_ctx(c->ssl->connection);

        cln = ngx_pool_cleanup_add(cctx->pool, 0);
        if (cln == NULL) {
            rc = NGX_ERROR;
            ngx_stream_lua_finalize_request(r, rc);
            return rc;
        }

        cln->handler = ngx_stream_lua_request_cleanup_handler;
        cln->data = ctx;
        ctx->cleanup = &cln->handler;
    }

    ctx->context = NGX_STREAM_LUA_CONTEXT_PROXY_SSL_CERT;

    rc = ngx_stream_lua_run_thread(L, r, ctx, 0);

    if (rc == NGX_ERROR || rc >= NGX_OK) {
        /* do nothing */

    } else if (rc == NGX_AGAIN) {
        rc = ngx_stream_lua_content_run_posted_threads(L, r, ctx, 0);

    } else if (rc == NGX_DONE) {
        rc = ngx_stream_lua_content_run_posted_threads(L, r, ctx, 1);

    } else {
        rc = NGX_OK;
    }

    ngx_stream_lua_finalize_request(r, rc);
    return rc;
}


int
ngx_stream_lua_ffi_proxy_ssl_get_tls1_version(ngx_stream_lua_request_t *r,
    char **err)
{
    ngx_stream_upstream_t           *u;
    ngx_ssl_conn_t                  *ssl_conn;
    ngx_connection_t                *c;

    u = r->session->upstream;
    if (u == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    c = u->peer.connection;
    if (c == NULL || c->ssl == NULL) {
        *err = "bad upstream connection";
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    dd("tls1 ver: %d", SSL_version(ssl_conn));

    return SSL_version(ssl_conn);
}


int
ngx_stream_lua_ffi_proxy_ssl_clear_certs(ngx_stream_lua_request_t *r,
    char **err)
{
    ngx_stream_upstream_t           *u;
    ngx_ssl_conn_t                  *ssl_conn;
    ngx_connection_t                *c;

    u = r->session->upstream;
    if (u == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    c = u->peer.connection;
    if (c == NULL || c->ssl == NULL) {
        *err = "bad upstream connection";
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    SSL_certs_clear(ssl_conn);
    return NGX_OK;
}


int
ngx_stream_lua_ffi_proxy_ssl_set_der_certificate(ngx_stream_lua_request_t *r,
    const char *data, size_t len, char **err)
{
    ngx_stream_upstream_t           *u;
    ngx_ssl_conn_t                  *ssl_conn;
    ngx_connection_t                *c;
    BIO                             *bio = NULL;
    X509                            *x509 = NULL;

    u = r->session->upstream;
    if (u == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    c = u->peer.connection;
    if (c == NULL || c->ssl == NULL) {
        *err = "bad upstream connection";
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    bio = BIO_new_mem_buf((char *) data, len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        goto failed;
    }

    x509 = d2i_X509_bio(bio, NULL);
    if (x509 == NULL) {
        *err = "d2i_X509_bio() failed";
        goto failed;
    }

    if (SSL_use_certificate(ssl_conn, x509) == 0) {
        *err = "SSL_use_certificate() failed";
        goto failed;
    }

    X509_free(x509);
    x509 = NULL;

    /* read rest of the chain */

    while (!BIO_eof(bio)) {

        x509 = d2i_X509_bio(bio, NULL);
        if (x509 == NULL) {
            *err = "d2i_X509_bio() failed";
            goto failed;
        }

        if (SSL_add0_chain_cert(ssl_conn, x509) == 0) {
            *err = "SSL_add0_chain_cert() failed";
            goto failed;
        }
    }

    BIO_free(bio);

    *err = NULL;
    return NGX_OK;

failed:

    if (bio) {
        BIO_free(bio);
    }

    if (x509) {
        X509_free(x509);
    }

    ERR_clear_error();

    return NGX_ERROR;
}


int
ngx_stream_lua_ffi_proxy_ssl_set_der_private_key(ngx_stream_lua_request_t *r,
    const char *data, size_t len, char **err)
{
    ngx_stream_upstream_t           *u;
    ngx_ssl_conn_t                  *ssl_conn;
    ngx_connection_t                *c;
    BIO                             *bio = NULL;
    EVP_PKEY                        *pkey = NULL;

    u = r->session->upstream;
    if (u == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    c = u->peer.connection;
    if (c == NULL || c->ssl == NULL) {
        *err = "bad upstream connection";
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    bio = BIO_new_mem_buf((char *) data, len);
    if (bio == NULL) {
        *err = "BIO_new_mem_buf() failed";
        goto failed;
    }

    pkey = d2i_PrivateKey_bio(bio, NULL);
    if (pkey == NULL) {
        *err = "d2i_PrivateKey_bio() failed";
        goto failed;
    }

    if (SSL_use_PrivateKey(ssl_conn, pkey) == 0) {
        *err = "SSL_use_PrivateKey() failed";
        goto failed;
    }

    EVP_PKEY_free(pkey);
    BIO_free(bio);

    return NGX_OK;

failed:

    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (bio) {
        BIO_free(bio);
    }

    ERR_clear_error();

    return NGX_ERROR;
}


int
ngx_stream_lua_ffi_proxy_ssl_set_cert(ngx_stream_lua_request_t *r,
    void *cdata, char **err)
{
#ifdef OPENSSL_IS_BORINGSSL
    size_t             i;
#else
    int                i;
#endif
    ngx_stream_upstream_t           *u;
    ngx_ssl_conn_t                  *ssl_conn;
    ngx_connection_t                *c;
    X509                            *x509 = NULL;
    STACK_OF(X509)                  *chain = cdata;

    u = r->session->upstream;
    if (u == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    c = u->peer.connection;
    if (c == NULL || c->ssl == NULL) {
        *err = "bad upstream connection";
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    if (sk_X509_num(chain) < 1) {
        *err = "invalid certificate chain";
        goto failed;
    }

    x509 = sk_X509_value(chain, 0);
    if (x509 == NULL) {
        *err = "sk_X509_value() failed";
        goto failed;
    }

    if (SSL_use_certificate(ssl_conn, x509) == 0) {
        *err = "SSL_use_certificate() failed";
        goto failed;
    }

    x509 = NULL;

    /* read rest of the chain */

    for (i = 1; i < sk_X509_num(chain); i++) {

        x509 = sk_X509_value(chain, i);
        if (x509 == NULL) {
            *err = "sk_X509_value() failed";
            goto failed;
        }

        if (SSL_add1_chain_cert(ssl_conn, x509) == 0) {
            *err = "SSL_add1_chain_cert() failed";
            goto failed;
        }
    }

    *err = NULL;
    return NGX_OK;

failed:

    ERR_clear_error();

    return NGX_ERROR;
}


int
ngx_stream_lua_ffi_proxy_ssl_set_priv_key(ngx_stream_lua_request_t *r,
    void *cdata, char **err)
{
    ngx_stream_upstream_t           *u;
    ngx_ssl_conn_t                  *ssl_conn;
    ngx_connection_t                *c;
    EVP_PKEY                        *pkey = NULL;

    u = r->session->upstream;
    if (u == NULL) {
        *err = "bad request";
        return NGX_ERROR;
    }

    c = u->peer.connection;
    if (c == NULL || c->ssl == NULL) {
        *err = "bad upstream connection";
        return NGX_ERROR;
    }

    ssl_conn = c->ssl->connection;
    if (ssl_conn == NULL) {
        *err = "bad ssl conn";
        return NGX_ERROR;
    }

    pkey = cdata;
    if (pkey == NULL) {
        *err = "invalid private key failed";
        goto failed;
    }

    if (SSL_use_PrivateKey(ssl_conn, pkey) == 0) {
        *err = "SSL_use_PrivateKey() failed";
        goto failed;
    }

    return NGX_OK;

failed:

    ERR_clear_error();

    return NGX_ERROR;
}

#endif /* HAVE_LUA_PROXY_SSL */
