/*
 * Copyright (c) 2024, TBox Keystore — TLS Mutual Authentication Demo
 *
 * Demonstrates TLS 1.2 mutual authentication where BOTH the server and
 * client private-key operations (RSA sign for CertificateVerify) happen
 * inside OP-TEE via the tbox_keystore ENGINE.
 *
 * Build:
 *   cmake .. && make                        (see CMakeLists.txt)
 *
 * Quick self-test (both processes on the same machine):
 *
 *   # 1. Provision keys in the TA (run once)
 *   tbox_keystore --init-pin 31323334
 *   tbox_keystore --gen-rsa server-key --size 2048 --sign --decrypt
 *   tbox_keystore --gen-rsa client-key --size 2048 --sign --decrypt
 *   tbox_keystore --lock
 *
 *   # 2. Start server in one terminal
 *   ./tls_mutual_auth --server
 *
 *   # 3. Run client in another terminal
 *   ./tls_mutual_auth --client
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

/* ---- Forward declaration of the ENGINE loader ---- */
extern int ENGINE_load_tbox_keystore(void);

/* ===================================================================
 *  Certificate helper — create a self-signed X.509 certificate
 *  whose public key comes from the EVP_PKEY (TA export) and whose
 *  private key stays in the TA.
 * =================================================================== */

static X509 *make_self_signed_cert(EVP_PKEY *pkey, const char *cn)
{
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	ASN1_INTEGER *serial = NULL;

	x509 = X509_new();
	if (!x509)
		goto err;

	/* Version 3 */
	X509_set_version(x509, 2);

	/* Serial number */
	serial = ASN1_INTEGER_new();
	if (!serial || !ASN1_INTEGER_set_uint64(serial, 1))
		goto err;
	X509_set_serialNumber(x509, serial);

	/* Validity: now → 10 years */
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509),  10L * 365 * 24 * 3600);

	/* Subject = Issuer = "/CN=<cn>" */
	name = X509_NAME_new();
	if (!name)
		goto err;
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (unsigned char *)cn, -1, -1, 0);
	X509_set_subject_name(x509, name);
	X509_set_issuer_name(x509, name);   /* self-signed */

	/* Set the public key from TA (exported via ENGINE) */
	X509_set_pubkey(x509, pkey);

	/*
	 * Sign the certificate with the private key — this call goes through
	 * ENGINE → TEEC → TA → TEE_AsymmetricSignDigest.
	 */
	if (!X509_sign(x509, pkey, EVP_sha256())) {
		fprintf(stderr, "X509_sign() failed — is the TA key loaded?\n");
		ERR_print_errors_fp(stderr);
		goto err;
	}

	fprintf(stdout, "[OK] Self-signed certificate created for '%s' "
		"(signed by TA)\n", cn);

	ASN1_INTEGER_free(serial);
	return x509;

err:
	X509_free(x509);
	ASN1_INTEGER_free(serial);
	return NULL;
}

/* ===================================================================
 *  TLS context setup
 * =================================================================== */

static SSL_CTX *create_tls_ctx(int server_mode,
			       const char *my_label,
			       X509 *my_cert,
			       X509 *peer_cert)
{
	SSL_CTX *ctx;

	if (server_mode)
		ctx = SSL_CTX_new(TLS_server_method());
	else
		ctx = SSL_CTX_new(TLS_client_method());

	if (!ctx) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		return NULL;
	}

	/* ---- Load ENGINE and bind private key ---- */
	{
		ENGINE *e = ENGINE_by_id("tbox_keystore");
		if (!e) {
			fprintf(stderr, "ENGINE_by_id(tbox_keystore) failed. "
				"Is e_tbox_keystore.so loaded?\n");
			goto err;
		}

		if (!ENGINE_init(e)) {
			fprintf(stderr, "ENGINE_init failed — "
				"check TA connectivity\n");
			ENGINE_free(e);
			goto err;
		}

		EVP_PKEY *pkey = ENGINE_load_private_key(e, my_label,
							  NULL, NULL);
		if (!pkey) {
			fprintf(stderr, "ENGINE_load_private_key('%s') failed. "
				"Was the key provisioned in the TA?\n",
				my_label);
			ENGINE_finish(e);
			ENGINE_free(e);
			goto err;
		}

		if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
			fprintf(stderr, "SSL_CTX_use_PrivateKey failed\n");
			EVP_PKEY_free(pkey);
			goto err;
		}
		fprintf(stdout, "[OK] Private key '%s' loaded from TA via ENGINE\n",
			my_label);

		EVP_PKEY_free(pkey);
	}

	/* ---- Bind certificate ---- */
	if (SSL_CTX_use_certificate(ctx, my_cert) != 1) {
		fprintf(stderr, "SSL_CTX_use_certificate failed\n");
		goto err;
	}

	/* ---- Peer verification (mutual auth) ---- */
	{
		X509_STORE *store = X509_STORE_new();
		X509_STORE_add_cert(store, peer_cert);
		SSL_CTX_set_cert_store(ctx, store);

		SSL_CTX_set_verify(ctx,
				   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
				   NULL);
	}

	/* TLS 1.2 only */
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

	return ctx;

err:
	SSL_CTX_free(ctx);
	return NULL;
}

/* ===================================================================
 *  Server
 * =================================================================== */

static int run_server(unsigned short port)
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int listen_fd = -1, client_fd = -1;
	struct sockaddr_in addr;
	X509 *server_cert = NULL, *client_cert = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = 1;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* ---- Load keys via ENGINE, create certs ---- */
	{
		ENGINE *e = ENGINE_by_id("tbox_keystore");
		if (!e || !ENGINE_init(e)) {
			fprintf(stderr, "ENGINE not available\n");
			return 1;
		}

		/* Server key */
		pkey = ENGINE_load_private_key(e, "server-key", NULL, NULL);
		if (!pkey) {
			fprintf(stderr, "Failed to load 'server-key'. "
				"Run: tbox_keystore --gen-rsa server-key\n");
			goto out;
		}
		server_cert = make_self_signed_cert(pkey, "tbox-server");
		if (!server_cert) goto out;

		/* Client key (for peer trust store) */
		EVP_PKEY *client_pkey = ENGINE_load_private_key(e, "client-key",
								 NULL, NULL);
		if (!client_pkey) {
			fprintf(stderr, "Failed to load 'client-key'. "
				"Run: tbox_keystore --gen-rsa client-key\n");
			goto out;
		}
		client_cert = make_self_signed_cert(client_pkey, "tbox-client");
		EVP_PKEY_free(client_pkey);
		if (!client_cert) goto out;

		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	/* ---- SSL context ---- */
	ctx = create_tls_ctx(1, "server-key", server_cert, client_cert);
	if (!ctx) goto out;

	/* ---- Socket ---- */
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) { perror("socket"); goto out; }

	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port        = htons(port);

	{
		int on = 1;
		setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	}

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind"); goto out;
	}
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

	/* Exchange a small application-level message */
	{
		const char *msg = "hello from tbox server (TA-signed)";
		char buf[256] = { 0 };

		SSL_write(ssl, msg, strlen(msg));
		int n = SSL_read(ssl, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			fprintf(stdout, "[SRV] Received: %s\n", buf);
		}
	}

	fprintf(stdout, "[SRV] TLS mutual-auth handshake SUCCESS.\n");
	{
		X509 *peer = SSL_get_peer_certificate(ssl);
		if (peer) {
			char *subj = X509_NAME_oneline(X509_get_subject_name(peer), NULL, 0);
			fprintf(stdout, "[SRV] Peer certificate: %s\n", subj);
			OPENSSL_free(subj);
			X509_free(peer);
		}
	}

	ret = 0;

out:
	if (ssl)        { SSL_shutdown(ssl); SSL_free(ssl); }
	if (client_fd >= 0) close(client_fd);
	if (listen_fd >= 0) close(listen_fd);
	SSL_CTX_free(ctx);
	X509_free(server_cert);
	X509_free(client_cert);

	return ret;
}

/* ===================================================================
 *  Client
 * =================================================================== */

static int run_client(const char *host, unsigned short port)
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int fd = -1;
	struct sockaddr_in addr;
	X509 *client_cert = NULL, *server_cert = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = 1;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* ---- Load keys via ENGINE, create certs ---- */
	{
		ENGINE *e = ENGINE_by_id("tbox_keystore");
		if (!e || !ENGINE_init(e)) {
			fprintf(stderr, "ENGINE not available\n");
			return 1;
		}

		/* Client key */
		pkey = ENGINE_load_private_key(e, "client-key", NULL, NULL);
		if (!pkey) {
			fprintf(stderr, "Failed to load 'client-key'. "
				"Run: tbox_keystore --gen-rsa client-key\n");
			goto out;
		}
		client_cert = make_self_signed_cert(pkey, "tbox-client");
		if (!client_cert) goto out;

		/* Server key (for trust store) */
		EVP_PKEY *server_pkey = ENGINE_load_private_key(e, "server-key",
								 NULL, NULL);
		if (!server_pkey) {
			fprintf(stderr, "Failed to load 'server-key'. "
				"Run: tbox_keystore --gen-rsa server-key\n");
			goto out;
		}
		server_cert = make_self_signed_cert(server_pkey, "tbox-server");
		EVP_PKEY_free(server_pkey);
		if (!server_cert) goto out;

		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	/* ---- SSL context ---- */
	ctx = create_tls_ctx(0, "client-key", client_cert, server_cert);
	if (!ctx) goto out;

	/* ---- Socket ---- */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); goto out; }

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(port);
	if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
		fprintf(stderr, "inet_pton failed\n");
		goto out;
	}

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		goto out;
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);

	if (SSL_connect(ssl) <= 0) {
		fprintf(stderr, "[CLI] SSL_connect failed\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}

	/* Exchange a small application-level message */
	{
		const char *msg = "hello from tbox client (TA-signed)";
		char buf[256] = { 0 };

		int n = SSL_read(ssl, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			fprintf(stdout, "[CLI] Received: %s\n", buf);
		}
		SSL_write(ssl, msg, strlen(msg));
	}

	fprintf(stdout, "[CLI] TLS mutual-auth handshake SUCCESS.\n");
	{
		X509 *peer = SSL_get_peer_certificate(ssl);
		if (peer) {
			char *subj = X509_NAME_oneline(X509_get_subject_name(peer), NULL, 0);
			fprintf(stdout, "[CLI] Peer certificate: %s\n", subj);
			OPENSSL_free(subj);
			X509_free(peer);
		}
	}

	ret = 0;

out:
	if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
	if (fd >= 0) close(fd);
	SSL_CTX_free(ctx);
	X509_free(client_cert);
	X509_free(server_cert);

	return ret;
}

/* ===================================================================
 *  Main
 * =================================================================== */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --server | --client\n"
		"\n"
		"TLS 1.2 mutual authentication demo with TEE-backed keys.\n"
		"Both the server and client private keys live inside OP-TEE.\n"
		"\n"
		"Prerequisites (run once):\n"
		"  tbox_keystore --init-pin <hex>\n"
		"  tbox_keystore --gen-rsa server-key --size 2048 --sign --decrypt\n"
		"  tbox_keystore --gen-rsa client-key --size 2048 --sign --decrypt\n"
		"  tbox_keystore --lock\n"
		"\n", prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	int server_mode = -1;

	if (argc == 2 && strcmp(argv[1], "--server") == 0)
		server_mode = 1;
	else if (argc == 2 && strcmp(argv[1], "--client") == 0)
		server_mode = 0;
	else
		usage(argv[0]);

	SSL_library_init();
	SSL_load_error_strings();

	fprintf(stdout, "========================================\n");
	fprintf(stdout, " TLS Mutual Auth Demo  (TEE-backed keys)\n");
	fprintf(stdout, " Mode   : %s\n", server_mode ? "SERVER" : "CLIENT");
	fprintf(stdout, " Engine : tbox_keystore\n");
	fprintf(stdout, "========================================\n\n");

	/* Load the ENGINE (dynamic or built-in).  The ENGINE's init
	 * callback opens the TEEC session to the TA. */
	if (!ENGINE_load_tbox_keystore()) {
		fprintf(stderr, "Failed to register tbox_keystore ENGINE\n");
		return 1;
	}

	if (server_mode)
		return run_server(9443);
	else
		return run_client("127.0.0.1", 9443);
}
