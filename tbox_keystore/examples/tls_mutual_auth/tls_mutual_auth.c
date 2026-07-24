/*
 * Copyright (c) 2024, TBox Keystore — TLS Mutual Authentication Demo
 *
 * TLS 1.2 mutual auth where both sides' CertificateVerify goes through
 * the tbox_keystore ENGINE (OP-TEE).  Each process loads only its own
 * private key from TA; peer certificates are read from files (generated
 * once with --gen-certs).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

extern int ENGINE_load_tbox_keystore(void);

#define SERVER_CERT_FILE  "/tmp/tbox-server.crt"
#define CLIENT_CERT_FILE  "/tmp/tbox-client.crt"

/* ---- Certificate helper ---- */

static X509 *make_self_signed_cert(EVP_PKEY *pkey, const char *cn)
{
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	ASN1_INTEGER *serial = NULL;

	x509 = X509_new();
	if (!x509) goto err;

	X509_set_version(x509, 2);

	serial = ASN1_INTEGER_new();
	if (!serial || !ASN1_INTEGER_set_uint64(serial, 1)) goto err;
	X509_set_serialNumber(x509, serial);

	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), 10L * 365 * 24 * 3600);

	name = X509_NAME_new();
	if (!name) goto err;
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (unsigned char *)cn, -1, -1, 0);
	X509_set_subject_name(x509, name);
	X509_set_issuer_name(x509, name);

	X509_set_pubkey(x509, pkey);

	if (!X509_sign(x509, pkey, EVP_sha256())) {
		fprintf(stderr, "X509_sign() failed\n");
		ERR_print_errors_fp(stderr);
		goto err;
	}
	fprintf(stdout, "[OK] Self-signed certificate '%s' (signed by TA)\n", cn);

	ASN1_INTEGER_free(serial);
	return x509;

err:
	X509_free(x509);
	ASN1_INTEGER_free(serial);
	return NULL;
}

static int save_cert(const char *path, X509 *cert)
{
	FILE *fp = fopen(path, "wb");
	if (!fp) { perror(path); return 0; }
	if (!PEM_write_X509(fp, cert)) { fclose(fp); return 0; }
	fclose(fp);
	fprintf(stdout, "[OK] Saved %s\n", path);
	return 1;
}

static X509 *load_cert(const char *path)
{
	FILE *fp = fopen(path, "rb");
	X509 *cert;
	if (!fp) { perror(path); return NULL; }
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!cert) fprintf(stderr, "Failed to load %s\n", path);
	return cert;
}

/* ---- Generate certs (run once) ---- */

static int gen_certs(void)
{
	ENGINE *e;
	EVP_PKEY *pkey;
	X509 *cert;

	ENGINE_load_tbox_keystore();
	e = ENGINE_by_id("tbox_keystore");
	if (!e || !ENGINE_init(e)) {
		fprintf(stderr, "ENGINE init failed\n");
		return 1;
	}

	/* Server cert */
	pkey = ENGINE_load_private_key(e, "server-key", NULL, NULL);
	if (!pkey) { fprintf(stderr, "server-key not found\n"); return 1; }
	cert = make_self_signed_cert(pkey, "tbox-server");
	EVP_PKEY_free(pkey);
	if (!cert) return 1;
	save_cert(SERVER_CERT_FILE, cert);
	X509_free(cert);

	/* Client cert */
	pkey = ENGINE_load_private_key(e, "client-key", NULL, NULL);
	if (!pkey) { fprintf(stderr, "client-key not found\n"); return 1; }
	cert = make_self_signed_cert(pkey, "tbox-client");
	EVP_PKEY_free(pkey);
	if (!cert) return 1;
	save_cert(CLIENT_CERT_FILE, cert);
	X509_free(cert);

	ENGINE_finish(e);
	return 0;
}

/* ---- TLS context ---- */

static SSL_CTX *create_tls_ctx(int server_mode,
			       const char *my_label,
			       X509 *my_cert,
			       X509 *peer_cert)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(server_mode ? TLS_server_method() : TLS_client_method());
	if (!ctx) return NULL;

	/* Load ENGINE key */
	{
		ENGINE *e = ENGINE_by_id("tbox_keystore");
		if (!e || !ENGINE_init(e)) {
			fprintf(stderr, "ENGINE not available\n");
			goto err;
		}
		EVP_PKEY *pkey = ENGINE_load_private_key(e, my_label, NULL, NULL);
		if (!pkey) {
			fprintf(stderr, "Failed to load '%s' from TA\n", my_label);
			goto err;
		}
		SSL_CTX_use_PrivateKey(ctx, pkey);
		fprintf(stdout, "[OK] '%s' loaded from TA via ENGINE\n", my_label);
		EVP_PKEY_free(pkey);
	}

	SSL_CTX_use_certificate(ctx, my_cert);

	/* Trust store — only the peer's self-signed cert */
	{
		X509_STORE *store = X509_STORE_new();
		X509_STORE_add_cert(store, peer_cert);
		SSL_CTX_set_cert_store(ctx, store);
		SSL_CTX_set_verify(ctx,
				   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
				   NULL);
	}

	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
	/* ECDHE-only: avoid RSA key-exchange which needs rsa_priv_dec (Phase 2). */
	SSL_CTX_set_cipher_list(ctx,
		"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");
	return ctx;

err:
	SSL_CTX_free(ctx);
	return NULL;
}

/* ---- Server ---- */

static int run_server(unsigned short port)
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int listen_fd = -1, client_fd = -1;
	struct sockaddr_in addr;
	X509 *my_cert = NULL, *peer_cert = NULL;
	int ret = 1;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	my_cert  = load_cert(SERVER_CERT_FILE);
	peer_cert = load_cert(CLIENT_CERT_FILE);
	if (!my_cert || !peer_cert) {
		fprintf(stderr, "Certs missing — run with --gen-certs first\n");
		goto out;
	}

	ctx = create_tls_ctx(1, "server-key", my_cert, peer_cert);
	if (!ctx) goto out;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) { perror("socket"); goto out; }

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port        = htons(port);
	{ int on = 1; setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)); }

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		{ perror("bind"); goto out; }
	if (listen(listen_fd, 1) < 0) { perror("listen"); goto out; }

	fprintf(stdout, "[SRV] Listening on :%u ...\n", port);

	client_fd = accept(listen_fd, NULL, NULL);
	if (client_fd < 0) { perror("accept"); goto out; }

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client_fd);

	if (SSL_accept(ssl) <= 0) {
		fprintf(stderr, "[SRV] SSL_accept failed\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}

	{
		const char *msg = "hello from tbox server (TA-signed)";
		char buf[256] = {0};
		SSL_write(ssl, msg, strlen(msg));
		int n = SSL_read(ssl, buf, sizeof(buf) - 1);
		if (n > 0) { buf[n] = '\0'; fprintf(stdout, "[SRV] Received: %s\n", buf); }
	}

	{
		X509 *peer = SSL_get_peer_certificate(ssl);
		if (peer) {
			char *s = X509_NAME_oneline(X509_get_subject_name(peer), NULL, 0);
			fprintf(stdout, "[SRV] Peer: %s\n", s);
			OPENSSL_free(s);
			X509_free(peer);
		}
	}

	fprintf(stdout, "[SRV] TLS mutual-auth SUCCESS.\n");
	ret = 0;

out:
	if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
	if (client_fd >= 0) close(client_fd);
	if (listen_fd >= 0) close(listen_fd);
	SSL_CTX_free(ctx);
	X509_free(my_cert);
	X509_free(peer_cert);
	return ret;
}

/* ---- Client ---- */

static int run_client(const char *host, unsigned short port)
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int fd = -1;
	struct sockaddr_in addr;
	X509 *my_cert = NULL, *peer_cert = NULL;
	int ret = 1;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	my_cert  = load_cert(CLIENT_CERT_FILE);
	peer_cert = load_cert(SERVER_CERT_FILE);
	if (!my_cert || !peer_cert) {
		fprintf(stderr, "Certs missing — run with --gen-certs first\n");
		goto out;
	}

	ctx = create_tls_ctx(0, "client-key", my_cert, peer_cert);
	if (!ctx) goto out;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); goto out; }

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
		{ fprintf(stderr, "inet_pton failed\n"); goto out; }

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		{ perror("connect"); goto out; }

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);

	if (SSL_connect(ssl) <= 0) {
		fprintf(stderr, "[CLI] SSL_connect failed\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}

	{
		const char *msg = "hello from tbox client (TA-signed)";
		char buf[256] = {0};
		int n = SSL_read(ssl, buf, sizeof(buf) - 1);
		if (n > 0) { buf[n] = '\0'; fprintf(stdout, "[CLI] Received: %s\n", buf); }
		SSL_write(ssl, msg, strlen(msg));
	}

	{
		X509 *peer = SSL_get_peer_certificate(ssl);
		if (peer) {
			char *s = X509_NAME_oneline(X509_get_subject_name(peer), NULL, 0);
			fprintf(stdout, "[CLI] Peer: %s\n", s);
			OPENSSL_free(s);
			X509_free(peer);
		}
	}

	fprintf(stdout, "[CLI] TLS mutual-auth SUCCESS.\n");
	ret = 0;

out:
	if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
	if (fd >= 0) close(fd);
	SSL_CTX_free(ctx);
	X509_free(my_cert);
	X509_free(peer_cert);
	return ret;
}

/* ---- Main ---- */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --gen-certs | --server | --client\n"
		"\n"
		"--gen-certs  Generate self-signed certs (run once)\n"
		"--server     Start TLS server\n"
		"--client     Connect to TLS server\n"
		"\n"
		"Prerequisites:\n"
		"  tbox_keystore --init-pin <hex>\n"
		"  tbox_keystore --gen-rsa server-key --size 2048 --sign\n"
		"  tbox_keystore --gen-rsa client-key --size 2048 --sign\n"
		"  %s --gen-certs\n"
		"\n", prog, prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	SSL_library_init();
	SSL_load_error_strings();
	ENGINE_load_tbox_keystore();

	if (argc != 2) usage(argv[0]);

	fprintf(stdout, "========================================\n");
	fprintf(stdout, " TLS Mutual Auth Demo  (TEE-backed keys)\n");
	fprintf(stdout, "========================================\n\n");

	if (strcmp(argv[1], "--gen-certs") == 0)
		return gen_certs();
	if (strcmp(argv[1], "--server") == 0)
		return run_server(9443);
	if (strcmp(argv[1], "--client") == 0)
		return run_client("127.0.0.1", 9443);

	usage(argv[0]);
	return 1;
}
