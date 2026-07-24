/*
 * mqtts_pub — MQTT publisher with TEE-backed TLS mutual auth.
 *
 * Follows the reference architecture:
 *   1. tbox_ssl_init()              — register ENGINE + external SSL callback
 *   2. MQTTClient_create(ssl://...) — paho in SSL mode
 *   3. privateKey="__EXTERNAL_CONFIG__" → paho calls our callback
 *   4. MQTTClient_connect           — TLS handshake (ENGINE → TA)
 *   5. publish message
 *
 * Build: see CMakeLists.txt
 * Usage: ./mqtts_pub [broker_host] [port] [topic] [message]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <MQTTClient.h>
#include <paho/SSLSocketConfig.h> /* SSLSocket_setExternalConfigCallback */

#include "ssl_config.h"           /* tbox_ssl_config() */

static int g_connected = 0;

static void on_conn_lost(void *ctx, char *cause)
{
	(void)ctx;
	fprintf(stderr, "[PUB] Connection lost: %s\n", cause ? cause : "?");
	g_connected = 0;
}

static void on_delivery(void *ctx, MQTTClient_deliveryToken tok)
{
	(void)ctx;
	fprintf(stdout, "[PUB] Delivery confirmed (token %d)\n", tok);
}

int main(int argc, char *argv[])
{
	const char *host  = (argc > 1) ? argv[1] : "127.0.0.1";
	int         port  = (argc > 2) ? atoi(argv[2]) : 8883;
	const char *topic = (argc > 3) ? argv[3] : "tbox/test";
	const char *msg   = (argc > 4) ? argv[4] : "hello from TBox (TA-signed)";

	char uri[256];
	MQTTClient client;
	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
	MQTTClient_SSLOptions     ssl_opts  = MQTTClient_SSLOptions_initializer;
	MQTTClient_message pub_msg = MQTTClient_message_initializer;
	MQTTClient_deliveryToken token;
	int rc;

	snprintf(uri, sizeof(uri), "ssl://%s:%d", host, port);

	fprintf(stdout, "\n=== MQTT Publisher (TEE ENGINE) ===\n");
	fprintf(stdout, "Broker: %s\n", uri);
	fprintf(stdout, "Topic:  %s\n", topic);

	/* Enable paho trace (must be BEFORE MQTTClient_create) */
	MQTTClient_setTraceLevel(MQTTCLIENT_TRACE_MAXIMUM);

	/* ---- 1. Register external SSL callback (like InitHsm + callback) ---- */
	SSLSocket_setExternalConfigCallback(tbox_ssl_config_pub);

	/* ---- 2. Create paho client ---- */
	rc = MQTTClient_create(&client, uri, "tbox-pub",
			       MQTTCLIENT_PERSISTENCE_NONE, NULL);
	if (rc != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "MQTTClient_create: %d (%s)\n",
			rc, MQTTClient_strerror(rc));
		return 1;
	}
	MQTTClient_setCallbacks(client, NULL, on_conn_lost,
				NULL, on_delivery);

	/* ---- 3. Connect with external SSL config ---- */
	ssl_opts.struct_version = 5;
	ssl_opts.privateKey     = "__EXTERNAL_CONFIG__";   /* triggers callback */

	conn_opts.keepAliveInterval = 60;
	conn_opts.cleansession     = 1;
	conn_opts.ssl              = &ssl_opts;
	conn_opts.connectTimeout   = 10;

	fprintf(stderr, "[PUB] connecting to %s timeout=%d\n",
		uri, conn_opts.connectTimeout);
	fprintf(stderr, "[PUB] ssl_opts.privateKey='%s' struct_version=%d\n",
		ssl_opts.privateKey, ssl_opts.struct_version);

	/* Enable paho trace (must be before MQTTClient_create) */
	MQTTClient_setTraceLevel(MQTTCLIENT_TRACE_MAXIMUM);

	/* Pre-flight: raw TCP check */
	{
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in sa;
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		inet_pton(AF_INET, host, &sa.sin_addr);
		if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
			fprintf(stderr, "[PUB] TCP connect OK\n");
			close(fd);
		} else {
			fprintf(stderr, "[PUB] TCP connect FAIL: %s\n", strerror(errno));
		}
	}

	rc = MQTTClient_connect(client, &conn_opts);
	if (rc != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "MQTTClient_connect: rc=%d (%s)\n",
			rc, MQTTClient_strerror(rc));
		MQTTClient_destroy(&client);
		return 1;
	}
	g_connected = 1;
	fprintf(stdout, "[PUB] Connected — TLS mutual auth via TA\n");

	/* ---- 4. Publish ---- */
	pub_msg.payload    = (void *)msg;
	pub_msg.payloadlen = (int)strlen(msg);
	pub_msg.qos        = 1;

	rc = MQTTClient_publishMessage(client, topic, &pub_msg, &token);
	if (rc != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "MQTTClient_publishMessage: %d\n", rc);
	} else {
		fprintf(stdout, "[PUB] Published: '%s'\n", msg);
	}

	/* ---- 5. Wait for delivery, then disconnect ---- */
	MQTTClient_waitForCompletion(client, token, 5000);
	MQTTClient_disconnect(client, 3000);
	MQTTClient_destroy(&client);

	fprintf(stdout, "=== DONE ===\n");
	return 0;
}
