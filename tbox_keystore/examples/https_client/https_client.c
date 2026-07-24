/*
 * HTTPS Client Demo — TEE-backed TLS mutual authentication.
 *
 * Connects to an openssl s_server instance.  The client private key
 * lives in OP-TEE (tbox_keystore TA); the ENGINE bridges OpenSSL to
 * the TA for the TLS CertificateVerify signature.
 *
 * Build:
 *   cmake .. && make   (adds https_client target, see CMakeLists.txt)
 *
 * Test flow:
 *   1. ./setup_keys.sh                 (generate TA keys + client cert)
 *   2. ./gen_sw_cert.sh                (generate server software cert)
 *   3. openssl s_server -port 9443 -cert /tmp/server-sw.crt \
 *        -key /tmp/server-sw.key -CAfile /tmp/tbox-client.crt \
 *        -verify 1 -Verify 1 &
 *   4. ./https_client
 *   5. Check output for "HTTP/1.1 200 OK"
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

extern int ENGINE_load_tbox_keystore(void);

#define SERVER_HOST       "127.0.0.1"
#define SERVER_PORT       9443
#define CLIENT_CERT_FILE  "/tmp/tbox-client.crt"
#define SERVER_CERT_FILE  "/tmp/server-sw.crt"

int main(void)
{
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	int fd = -1;
	struct sockaddr_in addr;
	int ret = 1;

	SSL_library_init();
	SSL_load_error_strings();

	fprintf(stdout, "\n=== HTTPS Client (TEE-backed key: client-key) ===\n\n");

	/* ---- 1. Register + init ENGINE ---- */
	fprintf(stdout, "[1] Loading TEE key 'client-key' via ENGINE ...\n");
	if (!ENGINE_load_tbox_keystore()) {
		fprintf(stderr, "FAIL: ENGINE_load_tbox_keystore\n");
		return 1;
	}

	/* ---- 2. Create SSL_CTX ---- */
	ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) { fprintf(stderr, "FAIL: SSL_CTX_new\n"); goto out; }

	/* Load client private key from TA */
	{
		ENGINE *e = ENGINE_by_id("tbox_keystore");
		if (!e || !ENGINE_init(e)) {
			fprintf(stderr, "FAIL: ENGINE init\n");
			goto out;
		}

		EVP_PKEY *pkey = ENGINE_load_private_key(e, "client-key",
							  NULL, NULL);
		if (!pkey) {
			fprintf(stderr, "FAIL: load 'client-key' from TA\n");
			ENGINE_finish(e);
			goto out;
		}

		if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
			fprintf(stderr, "FAIL: SSL_CTX_use_PrivateKey\n");
			EVP_PKEY_free(pkey);
			goto out;
		}
		EVP_PKEY_free(pkey);
		fprintf(stdout, "    OK\n");
	}

	/* Load client certificate (public, pre-generated) */
	if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT_FILE,
					 SSL_FILETYPE_PEM) != 1) {
		fprintf(stderr, "FAIL: load cert %s\n", CLIENT_CERT_FILE);
		goto out;
	}

	/* Trust server's self-signed certificate */
	if (SSL_CTX_load_verify_locations(ctx, SERVER_CERT_FILE, NULL) != 1) {
		fprintf(stderr, "FAIL: load CA %s\n", SERVER_CERT_FILE);
		goto out;
	}

	/* Mutual auth — require peer cert */
	SSL_CTX_set_verify(ctx,
			   SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			   NULL);

	/* TLS 1.2 only */
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

	/* ---- 3. Socket + connect ---- */
	fprintf(stdout, "[2] Connecting to %s:%u ...\n", SERVER_HOST,
		(unsigned int)SERVER_PORT);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); goto out; }

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port   = htons(SERVER_PORT);
	if (inet_pton(AF_INET, SERVER_HOST, &addr.sin_addr) != 1) {
		fprintf(stderr, "FAIL: inet_pton\n"); goto out;
	}

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect"); goto out;
	}
	fprintf(stdout, "    OK\n");

	/* ---- 4. TLS handshake ---- */
	fprintf(stdout, "[3] TLS handshake ...\n");

	ssl = SSL_new(ctx);
	if (!ssl) { fprintf(stderr, "FAIL: SSL_new\n"); goto out; }
	SSL_set_fd(ssl, fd);

	if (SSL_connect(ssl) <= 0) {
		fprintf(stderr, "FAIL: SSL_connect\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}

	fprintf(stdout, "    OK\n");
	fprintf(stdout, "    Cipher: %s\n", SSL_get_cipher(ssl));

	{
		X509 *peer = SSL_get_peer_certificate(ssl);
		if (peer) {
			char *subj = X509_NAME_oneline(
				X509_get_subject_name(peer), NULL, 0);
			fprintf(stdout, "    Server cert: %s\n", subj);
			OPENSSL_free(subj);
			X509_free(peer);
		}
	}

	/* ---- 5. HTTPS GET ---- */
	fprintf(stdout, "[4] GET / HTTP/1.1 ...\n\n");

	{
		const char *req =
			"GET / HTTP/1.1\r\n"
			"Host: test\r\n"
			"Connection: close\r\n"
			"\r\n";
		int wrote = SSL_write(ssl, req, strlen(req));
		if (wrote <= 0) {
			fprintf(stderr, "FAIL: SSL_write\n");
			ERR_print_errors_fp(stderr);
			goto out;
		}
	}

	/* ---- 6. Read and print HTTP response ---- */
	{
		char buf[4096];
		int n;
		while ((n = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0) {
			buf[n] = '\0';
			fputs(buf, stdout);
		}
		if (n < 0) {
			fprintf(stderr, "FAIL: SSL_read\n");
			ERR_print_errors_fp(stderr);
			goto out;
		}
	}

	fprintf(stdout, "\n=== DONE ===\n");
	ret = 0;

out:
	if (ssl)  { SSL_shutdown(ssl); SSL_free(ssl); }
	if (fd >= 0) close(fd);
	SSL_CTX_free(ctx);
	return ret;
}
