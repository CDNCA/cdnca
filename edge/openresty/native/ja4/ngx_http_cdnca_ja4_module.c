/*
 * ngx_http_cdnca_ja4_module: exposes the JA4 TLS client fingerprint of the
 * connection's first ClientHello as $cdnca_ja4 (cdnca).
 *
 * OpenSSL's client_hello callback exposes neither unknown extensions nor
 * their wire order, so the module registers an SSL message callback on every
 * HTTPS server context and fingerprints the raw ClientHello the moment the
 * handshake layer has reassembled it (before SNI selection and the client
 * hello callback run). The 36-byte result is kept in SSL ex_data, allocated
 * from the connection pool; a HelloRetryRequest's second ClientHello keeps
 * the first fingerprint. HTTP/2 streams share the connection's SSL object.
 *
 * HTTP/3 (QUIC) is not fingerprinted: the variable is not found there and on
 * plain-text connections, so logs and rules see an empty value.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "cdnca_ja4.h"

#if !(NGX_HTTP_SSL)
#error ngx_http_cdnca_ja4_module requires --with-http_ssl_module
#endif


static ngx_int_t ngx_http_cdnca_ja4_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_cdnca_ja4_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_cdnca_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_http_cdnca_ja4_message(int write_p, int version,
    int content_type, const void *buf, size_t len, ngx_ssl_conn_t *ssl_conn,
    void *arg);


static int  ngx_http_cdnca_ja4_index = -1;
static u_char  ngx_http_cdnca_ja4_failed[] = "";


static ngx_http_module_t  ngx_http_cdnca_ja4_module_ctx = {
    ngx_http_cdnca_ja4_add_variables,     /* preconfiguration */
    ngx_http_cdnca_ja4_init,              /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_cdnca_ja4_module = {
    NGX_MODULE_V1,
    &ngx_http_cdnca_ja4_module_ctx,       /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_cdnca_ja4_variables[] = {
    { ngx_string("cdnca_ja4"), NULL, ngx_http_cdnca_ja4_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
      ngx_http_null_variable
};


static ngx_int_t
ngx_http_cdnca_ja4_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_cdnca_ja4_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_cdnca_ja4_init(ngx_conf_t *cf)
{
    ngx_uint_t                   s;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    if (ngx_http_cdnca_ja4_index == -1) {
        ngx_http_cdnca_ja4_index = SSL_get_ex_new_index(0, NULL, NULL, NULL,
                                                         NULL);
        if (ngx_http_cdnca_ja4_index == -1) {
            ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                          "SSL_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    /* Every server context: the handshake starts on the listen default
     * server's context and SNI may switch it only after the ClientHello. */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        if (sscf != NULL && sscf->ssl.ctx != NULL) {
            SSL_CTX_set_msg_callback(sscf->ssl.ctx,
                                     ngx_http_cdnca_ja4_message);
        }
    }

    return NGX_OK;
}


static void
ngx_http_cdnca_ja4_message(int write_p, int version, int content_type,
    const void *buf, size_t len, ngx_ssl_conn_t *ssl_conn, void *arg)
{
    u_char            *ja4;
    const u_char      *message = buf;
    ngx_connection_t  *c;

    if (write_p || content_type != SSL3_RT_HANDSHAKE || len < 4
        || message[0] != SSL3_MT_CLIENT_HELLO
        || SSL_get_ex_data(ssl_conn, ngx_http_cdnca_ja4_index) != NULL)
    {
        return;
    }

    c = ngx_ssl_get_connection(ssl_conn);
    if (c == NULL || c->type != SOCK_STREAM
        || (((size_t) message[1] << 16) | ((size_t) message[2] << 8)
            | message[3]) != len - 4)
    {
        return;
    }

    ja4 = ngx_pnalloc(c->pool, CDNCA_JA4_LEN + 1);
    if (ja4 == NULL
        || cdnca_ja4_from_client_hello(message + 4, len - 4, 't',
                                        (char *) ja4)
           != 0)
    {
        ja4 = ngx_http_cdnca_ja4_failed;
    }

    if (SSL_set_ex_data(ssl_conn, ngx_http_cdnca_ja4_index, ja4) == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "cdnca ja4: ex_data failed");
    }
}


static ngx_int_t
ngx_http_cdnca_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char            *ja4;
    ngx_connection_t  *c = r->connection;

    v->not_found = 1;

#if (NGX_QUIC)
    if (c->quic) {
        return NGX_OK;
    }
#endif

    if (c->ssl == NULL || c->ssl->connection == NULL
        || ngx_http_cdnca_ja4_index == -1)
    {
        return NGX_OK;
    }

    ja4 = SSL_get_ex_data(c->ssl->connection, ngx_http_cdnca_ja4_index);
    if (ja4 == NULL || ja4[0] == '\0') {
        return NGX_OK;
    }

    v->data = ja4;
    v->len = CDNCA_JA4_LEN;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}
