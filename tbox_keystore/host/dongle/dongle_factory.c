/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Dongle factory — backend registration and auto-detection.
 *
 * Each backend registers itself by exposing a getter function:
 *   const struct dongle_ops *dongle_<name>_get_ops(void);
 *
 * The factory tries backends in priority order:
 *   YubiKey → Dummy
 */

#include <stdio.h>
#include <string.h>

#include "dongle_ops.h"

/* ---- Backend registration table ---- */
/* Each backend must declare its getter; weak symbols allow
 * backends to be compiled out without link errors. */

extern const struct dongle_ops *dongle_yubikey_get_ops(void)
	__attribute__((weak));

extern const struct dongle_ops *dongle_dummy_get_ops(void)
	__attribute__((weak));

/* Number of registered backends */
#define BACKEND_MAX 4

static const struct {
	const char *name;
	const struct dongle_ops *(*getter)(void);
} g_registry[BACKEND_MAX] = {
	{ "yubikey", dongle_yubikey_get_ops },
	{ "dummy",   dongle_dummy_get_ops   },
	{ NULL, NULL },
	{ NULL, NULL },
};

/*
 * Get a specific backend by name.
 * Returns NULL if not compiled in or not found.
 */
const struct dongle_ops *dongle_get(const char *name)
{
	int i;

	for (i = 0; i < BACKEND_MAX && g_registry[i].name; i++) {
		if (!g_registry[i].getter)
			continue; /* compiled out */
		if (strcmp(name, g_registry[i].name) == 0)
			return g_registry[i].getter();
	}

	return NULL;
}

/*
 * Auto-detect: try each backend's probe() in priority order.
 * Returns the first available backend, or NULL if none found.
 */
const struct dongle_ops *dongle_detect(void)
{
	int i;

	for (i = 0; i < BACKEND_MAX && g_registry[i].name; i++) {
		const struct dongle_ops *ops;

		if (!g_registry[i].getter)
			continue;

		ops = g_registry[i].getter();
		if (ops && ops->probe()) {
			fprintf(stderr, "[dongle] Auto-detected: %s\n", ops->name);
			return ops;
		}
	}

	fprintf(stderr, "[dongle] No dongle detected\n");
	return NULL;
}
