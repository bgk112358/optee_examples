/*
 * Copyright (c) 2026, TBox Keystore Example
 *
 * Remote signing dongle — the private key lives OUTSIDE the device.
 *
 * Loaded as a PLUGIN (`remote.so`) like any other backend.  "Plugging the
 * dongle in" here means: the driver is installed AND the remote signing
 * service is reachable and authorised.  The device never holds the key —
 * it only asks the remote service to sign the challenge.
 *
 *   device                                   remote (PC / cloud)
 *     CA ── ssh ──> tbox-dongle-sign sign <hex digest> ──> RSA-2048 sign
 *        <── hex(signature) ─────────────────────────────────┘
 *
 * Design: docs/32-dongle-plugin-architecture.md §7.
 *
 * Transports: `ssh` is implemented; `http_mtls` (cloud) is a reserved stub.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "dongle_ops.h"

/* ---- Tunables ---- */
#define RSA2048_SIG_LEN		256
#define PUBKEY_DER_MAX		512
#define HEX_BUF_MAX		(PUBKEY_DER_MAX * 2 + 2)
#define OUT_BUF_MAX		4096
#define ARGV_MAX		32

#define CFG_DEFAULT_PATH	"/etc/tbox/dongle/remote.conf"
#define CFG_DEFAULT_TIMEOUT_MS	2000
#define SSH_BIN_DEFAULT		"ssh"

/* ---- Configuration ----
 *
 * remote.conf is a flat `key = value` file; environment variables of the
 * form TBOX_REMOTE_DONGLE_<KEY> override it (handy for dev/CI, and lets a
 * test point ssh_bin at a local mock).
 */
struct remote_cfg {
	/* --- transport selection --- */
	char transport[32];	/* "ssh" (implemented) | "http_mtls" (reserved) */

	/* --- ssh transport --- */
	char ssh_bin[256];	/* not always "ssh": dropbear is "dbclient" */
	char host[256];
	char user[128];
	int  port;
	char key[512];		/* device's SSH private key */
	char known_hosts[512];
	int  timeout_ms;
	/*
	 * Prefix for the remote command line.  LEAVE EMPTY for the recommended
	 * deployment (sshd `command="... serve --device X"`): there sshd runs
	 * the forced command and hands us $SSH_ORIGINAL_COMMAND verbatim, so we
	 * must send ONLY the subcommand ("getpub") — prefixing it would make
	 * serve() treat the prefix as the subcommand name.
	 *
	 * Set it only when the account is a plain shell account where the full
	 * command has to be spelled out, e.g. "/opt/tbox-dongle-sign/tbox-dongle-sign".
	 */
	char remote_cmd[256];

	/* --- http_mtls transport (cloud) — PARSED but NOT implemented (P9) ---
	 * Parsed already so that a config written for the cloud form is not
	 * silently half-understood: unknown keys would otherwise be dropped
	 * without a trace.  See docs/32 §7.4 / §7.6.
	 */
	char endpoint[256];	/* https://ca.example.com/v1/dongle */
	char client_cert[512];	/* device certificate for mutual TLS */
	char client_key[512];	/* its private key */
};

static struct remote_cfg g_cfg;
static int  g_cfg_loaded;
static char g_plugin_dir[512];

void dongle_plugin_set_dir(const char *dir)
{
	snprintf(g_plugin_dir, sizeof(g_plugin_dir), "%s", dir ? dir : "");
}

static void cfg_defaults(void)
{
	memset(&g_cfg, 0, sizeof(g_cfg));
	snprintf(g_cfg.transport, sizeof(g_cfg.transport), "ssh");
	snprintf(g_cfg.ssh_bin, sizeof(g_cfg.ssh_bin), "%s", SSH_BIN_DEFAULT);
	/* remote_cmd intentionally left EMPTY — see the field comment above */
	g_cfg.port = 22;
	g_cfg.timeout_ms = CFG_DEFAULT_TIMEOUT_MS;
}

static void str_set(char *dst, size_t dst_len, const char *val)
{
	snprintf(dst, dst_len, "%s", val ? val : "");
}

static void cfg_set_kv(const char *k, const char *v)
{
	if (!strcmp(k, "transport"))        str_set(g_cfg.transport, sizeof(g_cfg.transport), v);
	else if (!strcmp(k, "ssh_bin"))     str_set(g_cfg.ssh_bin, sizeof(g_cfg.ssh_bin), v);
	else if (!strcmp(k, "host"))        str_set(g_cfg.host, sizeof(g_cfg.host), v);
	else if (!strcmp(k, "user"))        str_set(g_cfg.user, sizeof(g_cfg.user), v);
	else if (!strcmp(k, "port"))        g_cfg.port = atoi(v);
	else if (!strcmp(k, "key"))         str_set(g_cfg.key, sizeof(g_cfg.key), v);
	else if (!strcmp(k, "known_hosts")) str_set(g_cfg.known_hosts, sizeof(g_cfg.known_hosts), v);
	else if (!strcmp(k, "timeout_ms"))  g_cfg.timeout_ms = atoi(v);
	else if (!strcmp(k, "remote_cmd"))  str_set(g_cfg.remote_cmd, sizeof(g_cfg.remote_cmd), v);
	/* cloud (http_mtls) — reserved, parsed so nothing is silently dropped */
	else if (!strcmp(k, "endpoint"))    str_set(g_cfg.endpoint, sizeof(g_cfg.endpoint), v);
	else if (!strcmp(k, "client_cert")) str_set(g_cfg.client_cert, sizeof(g_cfg.client_cert), v);
	else if (!strcmp(k, "client_key"))  str_set(g_cfg.client_key, sizeof(g_cfg.client_key), v);
	/* unknown keys ignored: forward compatibility */
}

static const char *cfg_path(void)
{
	static char buf[600];
	const char *env = getenv("TBOX_REMOTE_DONGLE_CONF");

	if (env && *env)
		return env;
	if (g_plugin_dir[0]) {
		snprintf(buf, sizeof(buf), "%s/remote.conf", g_plugin_dir);
		if (access(buf, R_OK) == 0)
			return buf;
	}
	return CFG_DEFAULT_PATH;
}

static void cfg_load_file(void)
{
	char line[512];
	FILE *fp = fopen(cfg_path(), "r");

	if (!fp)
		return;		/* a missing file is fine: defaults + env apply */

	while (fgets(line, sizeof(line), fp)) {
		char *k, *v, *eq = strchr(line, '=');

		if (!eq || line[0] == '#')
			continue;
		*eq = '\0';
		k = line;
		v = eq + 1;
		while (*k && isspace((unsigned char)*k)) k++;
		{ char *e = k + strlen(k); while (e > k && isspace((unsigned char)e[-1])) *--e = '\0'; }
		while (*v && isspace((unsigned char)*v)) v++;
		{ char *e = v + strlen(v); while (e > v && isspace((unsigned char)e[-1])) *--e = '\0'; }
		if (*k)
			cfg_set_kv(k, v);
	}
	fclose(fp);
}

static void cfg_env_override(const char *suffix, const char *key)
{
	char name[128];
	const char *v;

	snprintf(name, sizeof(name), "TBOX_REMOTE_DONGLE_%s", suffix);
	v = getenv(name);
	if (v && *v)
		cfg_set_kv(key, v);
}

static void cfg_load(void)
{
	if (g_cfg_loaded)
		return;
	g_cfg_loaded = 1;

	cfg_defaults();
	cfg_load_file();

	cfg_env_override("TRANSPORT", "transport");
	cfg_env_override("SSH_BIN", "ssh_bin");
	cfg_env_override("HOST", "host");
	cfg_env_override("USER", "user");
	cfg_env_override("PORT", "port");
	cfg_env_override("KEY", "key");
	cfg_env_override("KNOWN_HOSTS", "known_hosts");
	cfg_env_override("TIMEOUT_MS", "timeout_ms");
	cfg_env_override("CMD", "remote_cmd");
	cfg_env_override("ENDPOINT", "endpoint");
	cfg_env_override("CLIENT_CERT", "client_cert");
	cfg_env_override("CLIENT_KEY", "client_key");
}

/* ---- Process helper: run argv, capture stdout, enforce a timeout ---- */

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * Run argv, capture its stdout into out, and kill it if it has not
 * finished within timeout_ms.  A SINGLE deadline covers both reading and
 * reaping — applying the budget twice would double the effective timeout.
 * Returns the child's exit status, or -1 on timeout / exec failure.
 */
static int run_capture(char *const argv[], char *out, size_t out_max, int timeout_ms)
{
	int pfd[2];
	pid_t pid;
	size_t used = 0;
	int status = 0;
	int rc = -1;
	long long deadline;

	if (timeout_ms <= 0)
		timeout_ms = CFG_DEFAULT_TIMEOUT_MS;
	deadline = now_ms() + timeout_ms;

	if (pipe(pfd) != 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}

	if (pid == 0) {
		/* child: stdout -> pipe, keep stderr for diagnostics */
		close(pfd[0]);
		if (dup2(pfd[1], STDOUT_FILENO) < 0)
			_exit(127);
		close(pfd[1]);
		execv(argv[0], argv);
		_exit(127);	/* exec failed (e.g. ssh not found) */
	}

	/* parent */
	close(pfd[1]);
	out[0] = '\0';

	{
		struct pollfd p = { .fd = pfd[0], .events = POLLIN };
		int eof = 0;

		while (!eof) {
			long long remain = deadline - now_ms();
			ssize_t n;

			if (remain <= 0)
				break;			/* deadline hit */
			/* stop before the buffer is exactly full: a zero-length
			 * read would otherwise look like EOF */
			if (used >= out_max - 1)
				break;

			if (poll(&p, 1, (int)remain) <= 0)
				break;			/* timeout (or error) */

			n = read(pfd[0], out + used, out_max - 1 - used);
			if (n > 0)
				used += (size_t)n;
			else if (n == 0)
				eof = 1;
			else if (errno != EINTR && errno != EAGAIN)
				break;
		}
	}

	close(pfd[0]);

	/* Reap against the SAME deadline */
	for (;;) {
		int wr = waitpid(pid, &status, WNOHANG);

		if (wr == pid)
			break;
		if (wr < 0)
			return -1;
		if (now_ms() >= deadline) {
			kill(pid, SIGKILL);
			waitpid(pid, &status, 0);
			return -1;		/* timed out */
		}
		usleep(5 * 1000);
	}

	out[used] = '\0';
	/* strip trailing newline(s) */
	while (used > 0 && (out[used - 1] == '\n' || out[used - 1] == '\r'))
		out[--used] = '\0';

	if (WIFEXITED(status))
		rc = WEXITSTATUS(status);
	else
		rc = -1;

	return rc;
}

/* ---- Transport abstraction (docs/32 §7.4) ---- */

struct transport {
	const char *name;
	/* Round-trip one subcommand.  Returns the remote exit code (0 = ok),
	 * or negative on local/transport failure.  `arg` may be NULL. */
	int (*call)(const char *subcmd, const char *arg, char *out, size_t out_max);
};

static int transport_ssh_call(const char *subcmd, const char *arg,
			      char *out, size_t out_max)
{
	char *argv[ARGV_MAX];
	char dest[400];
	char opt_timeout[64];
	char opt_kh[600];
	int n = 0;

	if (!g_cfg.host[0]) {
		fprintf(stderr, "[remote] ssh: host not configured (%s)\n", cfg_path());
		return -2;
	}

	snprintf(opt_timeout, sizeof(opt_timeout), "ConnectTimeout=%d",
		 g_cfg.timeout_ms > 0 ? (g_cfg.timeout_ms + 999) / 1000 : 2);

	argv[n++] = g_cfg.ssh_bin;
	argv[n++] = "-o"; argv[n++] = "BatchMode=yes";
	argv[n++] = "-o"; argv[n++] = "NumberOfPasswordPrompts=0";
	/*
	 * Host-key checking is mandatory: without it an attacker can MITM
	 * the connection and impersonate the signing service (§10.1 #1).
	 */
	argv[n++] = "-o"; argv[n++] = "StrictHostKeyChecking=yes";
	argv[n++] = "-o"; argv[n++] = opt_timeout;
	if (g_cfg.known_hosts[0]) {
		snprintf(opt_kh, sizeof(opt_kh), "UserKnownHostsFile=%s", g_cfg.known_hosts);
		argv[n++] = "-o"; argv[n++] = opt_kh;
	}
	if (g_cfg.key[0]) {
		argv[n++] = "-i"; argv[n++] = g_cfg.key;
	}
	if (g_cfg.port > 0) {
		static char port_str[8];
		snprintf(port_str, sizeof(port_str), "%d", g_cfg.port);
		argv[n++] = "-p"; argv[n++] = port_str;
	}
	snprintf(dest, sizeof(dest), "%s@%s",
		 g_cfg.user[0] ? g_cfg.user : "root", g_cfg.host);
	argv[n++] = dest;
	/* only prefix the helper name when explicitly configured (see struct) */
	if (g_cfg.remote_cmd[0])
		argv[n++] = g_cfg.remote_cmd;
	argv[n++] = (char *)subcmd;
	if (arg)
		argv[n++] = (char *)arg;
	argv[n++] = NULL;

	if (n >= ARGV_MAX)
		return -2;

	return run_capture(argv, out, out_max, g_cfg.timeout_ms);
}

/*
 * Cloud transport — INTERFACE RESERVED, NOT IMPLEMENTED (docs/32 §7.4 / P9).
 *
 * The vtable slot and the config keys (endpoint / client_cert / client_key)
 * exist so that the cloud form can be dropped in later without touching the
 * callers: implementing it means filling in this function (an HTTPS client
 * with mutual TLS) and nothing else.
 *
 * It fails loudly rather than silently succeeding: a misconfigured device
 * must not look like "no dongle".
 */
static int transport_http_mtls_call(const char *subcmd, const char *arg,
				    char *out, size_t out_max)
{
	(void)subcmd; (void)arg;

	fprintf(stderr,
		"[remote] transport 'http_mtls' is RESERVED, not implemented yet "
		"(docs/32 §7.4 / P9).\n"
		"         Use transport=ssh for now.\n");
	if (!g_cfg.endpoint[0])
		fprintf(stderr, "         (endpoint is not set either.)\n");

	if (out && out_max)
		snprintf(out, out_max, "http_mtls not implemented");
	return -3;
}

static const struct transport g_transport_ssh = { "ssh", transport_ssh_call };
static const struct transport g_transport_http = { "http_mtls", transport_http_mtls_call };

static const struct transport *transport_get(void)
{
	cfg_load();
	if (!strcmp(g_cfg.transport, "ssh"))
		return &g_transport_ssh;
	if (!strcmp(g_cfg.transport, "http_mtls"))
		return &g_transport_http;
	fprintf(stderr, "[remote] unknown transport '%s' (valid: ssh, http_mtls)\n",
		g_cfg.transport);
	return NULL;
}

/* ---- Helpers ---- */

static int hex_decode(const char *hex, uint8_t *out, size_t out_max, size_t *out_len)
{
	size_t len, i;

	if (!hex)
		return -1;
	len = strlen(hex);
	if (len == 0 || len % 2 != 0 || len / 2 > out_max)
		return -1;

	for (i = 0; i < len / 2; i++) {
		unsigned int b;
		if (sscanf(hex + i * 2, "%2x", &b) != 1)
			return -1;
		out[i] = (uint8_t)b;
	}
	*out_len = len / 2;
	return 0;
}

/* ---- Per-instance state ---- */

struct dongle_ctx {
	uint8_t pubkey_der[PUBKEY_DER_MAX];
	size_t  pubkey_len;
};

/* ---- probe: is the remote reachable and answering? ---- */

static int remote_probe(void)
{
	const struct transport *t = transport_get();
	char out[OUT_BUF_MAX];

	if (!t)
		return 0;
	/* config validation belongs to the transport (ssh needs host, cloud
	 * needs endpoint) — see transport_*_call() */
	if (t->call("ping", NULL, out, sizeof(out)) != 0)
		return 0;
	return strcmp(out, "OK") == 0;
}

/* ---- open: validate config + fetch (and cache) the public key ---- */

static int remote_open(struct dongle_ctx **ctx_out)
{
	const struct transport *t = transport_get();
	struct dongle_ctx *ctx;
	char out[OUT_BUF_MAX];
	size_t der_len;
	int rc;

	if (!t)
		return -1;

	rc = t->call("getpub", NULL, out, sizeof(out));
	if (rc != 0) {
		fprintf(stderr, "[remote] getpub failed (rc=%d)\n", rc);
		return -1;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	if (hex_decode(out, ctx->pubkey_der, sizeof(ctx->pubkey_der), &der_len) != 0) {
		fprintf(stderr, "[remote] malformed public key from remote\n");
		free(ctx);
		return -1;
	}
	ctx->pubkey_len = der_len;

	fprintf(stderr, "[remote] connected: %s@%s (%zu-byte pubkey)\n",
		g_cfg.user[0] ? g_cfg.user : "root", g_cfg.host, der_len);

	*ctx_out = ctx;
	return 0;
}

static void remote_close(struct dongle_ctx *ctx)
{
	free(ctx);
}

/* ---- sign: ask the remote to sign the 32-byte digest ---- */

static int remote_sign(struct dongle_ctx *ctx,
		       const uint8_t *digest, size_t digest_len,
		       uint8_t *sig_der, size_t *sig_len)
{
	const struct transport *t = transport_get();
	char hex[HEX_BUF_MAX];
	char out[OUT_BUF_MAX];
	size_t out_len;
	size_t i;
	int rc;

	if (!ctx || !t || digest_len != 32 || !sig_len)
		return -1;
	if (*sig_len < RSA2048_SIG_LEN) {
		fprintf(stderr, "[remote] signature buffer too small (%zu < %d)\n",
			*sig_len, RSA2048_SIG_LEN);
		return -1;
	}

	for (i = 0; i < digest_len; i++)
		sprintf(hex + i * 2, "%02x", digest[i]);
	hex[digest_len * 2] = '\0';

	rc = t->call("sign", hex, out, sizeof(out));
	if (rc != 0) {
		fprintf(stderr, "[remote] sign rejected (rc=%d)\n", rc);
		return -1;
	}

	if (hex_decode(out, sig_der, *sig_len, &out_len) != 0) {
		fprintf(stderr, "[remote] malformed signature\n");
		return -1;
	}
	if (out_len != RSA2048_SIG_LEN) {
		fprintf(stderr, "[remote] unexpected signature length %zu\n", out_len);
		return -1;
	}

	*sig_len = out_len;
	return 0;
}

/* ---- get_pubkey: cached from open() ---- */

static int remote_get_pubkey(struct dongle_ctx *ctx,
			     uint8_t *pubkey_der, size_t *pubkey_len)
{
	if (!ctx || !pubkey_len || *pubkey_len < ctx->pubkey_len)
		return -1;
	memcpy(pubkey_der, ctx->pubkey_der, ctx->pubkey_len);
	*pubkey_len = ctx->pubkey_len;
	return 0;
}

/* ---- get_serial: not offered by the remote service ---- */

static int remote_get_serial(struct dongle_ctx *ctx, uint32_t *serial)
{
	(void)ctx; (void)serial;
	return -1;	/* caller skips serial verification */
}

/* ---- get_attr: parsed from the remote `info` output ---- */

static int remote_get_attr(struct dongle_ctx *ctx,
			   const char *key, char *val, size_t val_len)
{
	const struct transport *t = transport_get();
	char out[OUT_BUF_MAX];
	char *line;
	int rc;

	(void)ctx;
	if (!t || !key || !val)
		return -1;

	rc = t->call("info", NULL, out, sizeof(out));
	if (rc != 0)
		return -1;

	for (line = strtok(out, "\n"); line; line = strtok(NULL, "\n")) {
		char *eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		if (strcmp(line, key) == 0) {
			snprintf(val, val_len, "%s", eq + 1);
			return 0;
		}
	}
	return -1;
}

/* ---- Ops table ---- */

static struct dongle_ops remote_ops = {
	.name       = "remote",
	.key_type   = "RSA-2048",
	.caps       = DONGLE_CAP_SIGN | DONGLE_CAP_GET_PUBKEY | DONGLE_CAP_GET_ATTR,
	.priority   = 20,	/* preferred over the local dummy */
	.probe      = remote_probe,
	.open       = remote_open,
	.close      = remote_close,
	.sign       = remote_sign,
	.get_pubkey = remote_get_pubkey,
	.get_serial = remote_get_serial,
	.get_attr   = remote_get_attr,
};

/* ---- Plugin entry points ---- */

const struct dongle_ops *dongle_plugin_get_ops(void)
{
	return &remote_ops;
}

uint32_t dongle_plugin_abi_version(void)
{
	return DONGLE_PLUGIN_ABI_VERSION;
}
