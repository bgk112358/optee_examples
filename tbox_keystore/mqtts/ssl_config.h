/*
 * SSL config callback for paho external SSL config.
 *
 * tbox_ssl_config_ex(ctx, key_label, cert_file) — injects everything.
 * tbox_ssl_config(ctx) — convenience wrapper for backward compat.
 */
#ifndef TBOX_SSL_CONFIG_H
#define TBOX_SSL_CONFIG_H

#include <openssl/ssl.h>

int tbox_ssl_config_ex(SSL_CTX *ctx, const char *key_label,
                       const char *cert_file);

/* Convenience wrappers — match SSLSocket_externalConfigCallback signature */
static inline int tbox_ssl_config_pub(SSL_CTX *ctx)
{ return tbox_ssl_config_ex(ctx, "pub-key", "/tmp/pub.crt"); }

static inline int tbox_ssl_config_sub(SSL_CTX *ctx)
{ return tbox_ssl_config_ex(ctx, "sub-key", "/tmp/sub.crt"); }

#endif
