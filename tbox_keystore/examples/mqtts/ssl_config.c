/*
 * SSL config — inject TEE ENGINE key + CA-signed cert into SSL_CTX.
 *
 * Each process (pub / sub) uses its own TA key label.
 * All trust the same Root CA.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>

#define CA_CERT      "/tmp/root-ca.crt"

extern int ENGINE_load_tbox_keystore(void);

static int g_engine_ready = 0;

int tbox_ssl_config_ex(SSL_CTX *ctx, const char *key_label,
                       const char *cert_file)
{
	ENGINE *e;

	fprintf(stderr, "ssl_config: ENTER key=%s cert=%s ca=%s\n",
		key_label ? key_label : "(null)",
		cert_file ? cert_file : "(null)", CA_CERT);

	if (!ctx || !key_label || !cert_file) {
		fprintf(stderr, "ssl_config: bad args (ctx=%p)\n", (void*)ctx);
		return -1;
	}

	/* ---- 1. Register + init ENGINE (once per process) ---- */
	if (!g_engine_ready) {
		if (!ENGINE_load_tbox_keystore()) {
			fprintf(stderr, "ssl_config: ENGINE_load failed\n");
			return -1;
		}
	}

	e = ENGINE_by_id("tbox_keystore");
	if (!e) {
		fprintf(stderr, "ssl_config: ENGINE_by_id failed\n");
		return -1;
	}
	if (!ENGINE_init(e)) {
		fprintf(stderr, "ssl_config: ENGINE_init failed\n");
		return -1;
	}
	g_engine_ready = 1;

	/* ---- 2. Load private key from TA ---- */
	{
		EVP_PKEY *pkey = ENGINE_load_private_key(e, key_label,
							  NULL, NULL);
		if (!pkey) {
			fprintf(stderr, "ssl_config: "
				"ENGINE_load_private_key('%s') failed\n",
				key_label);
			return -1;
		}
		if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
			fprintf(stderr, "ssl_config: "
				"SSL_CTX_use_PrivateKey failed\n");
			EVP_PKEY_free(pkey);
			return -1;
		}
		EVP_PKEY_free(pkey);
	}

	/* ---- 3. Load own certificate (CA-signed) ---- */
	if (SSL_CTX_use_certificate_file(ctx, cert_file,
					 SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "ssl_config: "
			"SSL_CTX_use_certificate_file(%s) failed\n",
			cert_file);
		return -1;
	}

	/* ---- 4. Trust Root CA ---- */
	if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) != 1) {
		fprintf(stderr, "ssl_config: "
			"SSL_CTX_load_verify_locations(%s) failed\n",
			CA_CERT);
		return -1;
	}
	SSL_CTX_set_verify(ctx,
			   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			   NULL);

	fprintf(stdout, "ssl_config: OK (key=%s, cert=%s, ca=%s)\n",
		key_label, cert_file, CA_CERT);
	return 0;
}
