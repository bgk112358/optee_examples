/*
 * Minimal paho MQTT TCP probe — no SSL, no ENGINE.
 * Isolates whether paho itself can connect to the broker.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <MQTTClient.h>

int main(int argc, char *argv[])
{
	const char *host = (argc > 1) ? argv[1] : "192.168.100.48";
	int port = (argc > 2) ? atoi(argv[2]) : 1883;
	char uri[256];
	MQTTClient client;
	int rc;

	snprintf(uri, sizeof(uri), "tcp://%s:%d", host, port);

	printf("[tcpprobe] paho TCP to %s ...\n", uri);

	rc = MQTTClient_create(&client, uri, "tcpprobe",
			       MQTTCLIENT_PERSISTENCE_NONE, NULL);
	if (rc != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "[tcpprobe] create: %d (%s)\n",
			rc, MQTTClient_strerror(rc));
		return 1;
	}

	MQTTClient_connectOptions opts = MQTTClient_connectOptions_initializer;
	opts.keepAliveInterval = 10;
	opts.cleansession = 1;
	opts.connectTimeout = 5;

	rc = MQTTClient_connect(client, &opts);
	if (rc != MQTTCLIENT_SUCCESS) {
		fprintf(stderr, "[tcpprobe] connect: %d (%s)\n",
			rc, MQTTClient_strerror(rc));
		MQTTClient_destroy(&client);
		return 1;
	}

	printf("[tcpprobe] CONNECT OK — paho MQTT/TCP works\n");
	MQTTClient_disconnect(client, 1000);
	MQTTClient_destroy(&client);
	return 0;
}
