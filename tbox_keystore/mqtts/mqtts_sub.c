/*
 * mqtts_sub — MQTT subscriber with TEE-backed TLS mutual auth.
 *
 * Build: see CMakeLists.txt
 * Usage: ./mqtts_sub [broker_host] [port] [topic] [timeout_sec]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <MQTTClient.h>
#include <paho/SSLSocketConfig.h>

#include "ssl_config.h"

static volatile int g_running = 1;

static void sig_handler(int s) { (void)s; g_running = 0; }

static int g_msg_cnt = 0;

static int on_msg(void *ctx, char *topic, int topic_len,
		  MQTTClient_message *msg)
{
	(void)ctx;
	fprintf(stdout, "[SUB] topic=%.*s payload=%.*s\n",
		topic_len, topic, msg->payloadlen, (char *)msg->payload);
	g_msg_cnt++;
	MQTTClient_freeMessage(&msg);
	MQTTClient_free(topic);
	return 1;
}

static void on_conn_lost(void *ctx, char *cause)
{
	(void)ctx;
	fprintf(stderr, "[SUB] Connection lost: %s\n", cause ? cause : "?");
}

int main(int argc, char *argv[])
{
	const char *host    = (argc > 1) ? argv[1] : "127.0.0.1";
	int         port    = (argc > 2) ? atoi(argv[2]) : 8883;
	const char *topic   = (argc > 3) ? argv[3] : "tbox/test";
	int         timeout = (argc > 4) ? atoi(argv[4]) : 30;

	char uri[256];
	MQTTClient client;
	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
	MQTTClient_SSLOptions     ssl_opts  = MQTTClient_SSLOptions_initializer;
	int rc;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	snprintf(uri, sizeof(uri), "ssl://%s:%d", host, port);

	fprintf(stdout, "\n=== MQTT Subscriber (TEE ENGINE) ===\n");
	fprintf(stdout, "Broker:  %s\n", uri);
	fprintf(stdout, "Topic:   %s\n", topic);
	fprintf(stdout, "Timeout: %d s\n", timeout);

	/* ---- 1. Register external SSL callback ---- */
	SSLSocket_setExternalConfigCallback(tbox_ssl_config_sub);

	/* ---- 2. Create paho client ---- */
	rc = MQTTClient_create(&client, uri, "tbox-sub",
			       MQTTCLIENT_PERSISTENCE_NONE, NULL);
	if (rc != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "MQTTClient_create: %d (%s)\n",
			rc, MQTTClient_strerror(rc));
		return 1;
	}
	MQTTClient_setCallbacks(client, NULL, on_conn_lost, on_msg, NULL);

	/* ---- 3. Connect ---- */
	ssl_opts.struct_version = 5;
	ssl_opts.privateKey     = "__EXTERNAL_CONFIG__";

	conn_opts.keepAliveInterval = 60;
	conn_opts.cleansession     = 1;
	conn_opts.ssl              = &ssl_opts;
	conn_opts.connectTimeout   = 10;

	fprintf(stderr, "[SUB] connecting to %s timeout=%d\n",
		uri, conn_opts.connectTimeout);
	fprintf(stderr, "[SUB] ssl_opts.privateKey='%s' struct_version=%d\n",
		ssl_opts.privateKey, ssl_opts.struct_version);

	rc = MQTTClient_connect(client, &conn_opts);
	if (rc != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "MQTTClient_connect: rc=%d (%s)\n",
			rc, MQTTClient_strerror(rc));
		MQTTClient_destroy(&client);
		return 1;
	}
	fprintf(stdout, "[SUB] Connected — TLS mutual auth via TA\n");

	/* ---- 4. Subscribe ---- */
	rc = MQTTClient_subscribe(client, topic, 1);
	if (rc != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "subscribe: %d (%s)\n",
			rc, MQTTClient_strerror(rc));
		goto out;
	}
	fprintf(stdout, "[SUB] Subscribed to '%s'\n", topic);

	/* ---- 5. Wait for messages ---- */
	{
		int elapsed = 0;
		while (g_running && elapsed < timeout) {
			MQTTClient_yield();
			usleep(100000);   /* 100 ms */
			elapsed++;
		}
	}

	if (g_msg_cnt == 0)
		fprintf(stdout, "[SUB] No messages received in %d s\n", timeout);

out:
	fprintf(stdout, "[SUB] Disconnecting...\n");
	MQTTClient_disconnect(client, 3000);
	MQTTClient_destroy(&client);
	fprintf(stdout, "=== DONE ===\n");
	return 0;
}
