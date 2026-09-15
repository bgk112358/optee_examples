/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Dongle factory — run-time plugin loader.
 *
 * Backends are no longer linked in at build time.  On first use this
 * module scans a directory for *.so files, dlopen()s each one, checks its
 * reported ABI version and keeps its ops table.  Dropping a .so into the
 * directory is therefore equivalent to "installing a dongle driver".
 *
 *   default dir : /usr/lib/tbox/dongle/
 *   override    : $TBOX_DONGLE_DIR
 *
 * The public API (dongle_detect / dongle_get) is unchanged, so callers
 * such as keystore_client.c need no modification.
 *
 * See docs/32-dongle-plugin-architecture.md §5-§7.
 */

#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dongle_ops.h"

#define DONGLE_DIR_DEFAULT	"/usr/lib/tbox/dongle"
#define PLUGIN_MAX		8
#define PATH_MAX_LEN		512

/* ---- Loaded plugins ---- */
static struct {
	const struct dongle_ops *ops;
	void                    *dl;	/* dlopen handle (never closed) */
} g_plugins[PLUGIN_MAX];
static int  g_plugin_cnt;
static int  g_loaded;			/* one-shot scan guard */

static const char *dongle_dir(void)
{
	const char *env = getenv("TBOX_DONGLE_DIR");

	return (env && *env) ? env : DONGLE_DIR_DEFAULT;
}

static int has_suffix(const char *s, const char *suffix)
{
	size_t ls = strlen(s);
	size_t lx = strlen(suffix);

	return ls > lx && strcmp(s + ls - lx, suffix) == 0;
}

/*
 * Load one plugin.
 *
 * Returns 0 on success.  Every failure path is non-fatal: a broken or
 * incompatible plugin is reported and skipped, the rest still load.
 */
static int load_plugin(const char *dir, const char *file)
{
	char path[PATH_MAX_LEN];
	void *dl;
	uint32_t (*abi_ver)(void);
	const struct dongle_ops *(*get_ops)(void);
	void (*set_dir)(const char *);
	const struct dongle_ops *ops;

	if (snprintf(path, sizeof(path), "%s/%s", dir, file) >= (int)sizeof(path)) {
		fprintf(stderr, "[dongle] path too long, skipping: %s\n", file);
		return -1;
	}

	if (g_plugin_cnt >= PLUGIN_MAX) {
		fprintf(stderr, "[dongle] plugin limit (%d) reached, skipping %s\n",
			PLUGIN_MAX, file);
		return -1;
	}

	/* RTLD_LOCAL: don't pollute the global symbol namespace */
	dl = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!dl) {
		fprintf(stderr, "[dongle] cannot load %s: %s\n", file, dlerror());
		return -1;
	}

	/* Both entry points are mandatory */
	abi_ver = (uint32_t (*)(void))dlsym(dl, DONGLE_PLUGIN_SYM_ABI_VER);
	get_ops = (const struct dongle_ops *(*)(void))dlsym(dl,
						DONGLE_PLUGIN_SYM_GET_OPS);
	if (!abi_ver || !get_ops) {
		fprintf(stderr, "[dongle] %s is not a dongle plugin "
			"(missing %s / %s)\n", file,
			DONGLE_PLUGIN_SYM_ABI_VER, DONGLE_PLUGIN_SYM_GET_OPS);
		dlclose(dl);
		return -1;
	}

	/* ABI guard: refuse mismatched plugins rather than crash later */
	if (abi_ver() != DONGLE_PLUGIN_ABI_VERSION) {
		fprintf(stderr, "[dongle] %s: ABI mismatch (plugin=%u, host=%u) "
			"— refusing to load\n", file,
			abi_ver(), DONGLE_PLUGIN_ABI_VERSION);
		dlclose(dl);
		return -1;
	}

	/* Optional: tell the plugin where it lives (for companion key files) */
	set_dir = (void (*)(const char *))dlsym(dl, DONGLE_PLUGIN_SYM_SET_DIR);
	if (set_dir)
		set_dir(dir);

	ops = get_ops();
	if (!ops || !ops->name || !ops->probe) {
		fprintf(stderr, "[dongle] %s: invalid ops table\n", file);
		dlclose(dl);
		return -1;
	}

	g_plugins[g_plugin_cnt].ops = ops;
	g_plugins[g_plugin_cnt].dl  = dl;
	g_plugin_cnt++;

	fprintf(stderr, "[dongle] loaded plugin: %s (%s)\n",
		ops->name, ops->key_type ? ops->key_type : "?");
	return 0;
}

/* Highest priority first; ties broken by name so the order is stable */
static int plugin_cmp(const void *a, const void *b)
{
	const struct dongle_ops *oa = ((const typeof(g_plugins[0]) *)a)->ops;
	const struct dongle_ops *ob = ((const typeof(g_plugins[0]) *)b)->ops;

	if (oa->priority != ob->priority)
		return (oa->priority < ob->priority) ? 1 : -1;
	return strcmp(oa->name, ob->name);
}

static void scan_once(void)
{
	const char *dir = dongle_dir();
	DIR *d;
	struct dirent *e;

	if (g_loaded)
		return;
	g_loaded = 1;

	d = opendir(dir);
	if (!d) {
		/* A missing directory simply means "no dongle drivers installed" */
		fprintf(stderr, "[dongle] no plugin directory: %s\n", dir);
		return;
	}

	while ((e = readdir(d)) != NULL) {
		if (!has_suffix(e->d_name, ".so"))
			continue;
		load_plugin(dir, e->d_name);
	}
	closedir(d);

	if (g_plugin_cnt > 1)
		qsort(g_plugins, (size_t)g_plugin_cnt, sizeof(g_plugins[0]),
		      plugin_cmp);
}

/*
 * Get a specific backend by name.
 * Returns NULL if not loaded or not found.
 */
const struct dongle_ops *dongle_get(const char *name)
{
	int i;

	if (!name)
		return NULL;

	scan_once();

	for (i = 0; i < g_plugin_cnt; i++) {
		if (strcmp(name, g_plugins[i].ops->name) == 0)
			return g_plugins[i].ops;
	}

	return NULL;
}

/*
 * Auto-detect: try each loaded plugin's probe() in priority order.
 * Returns the first available backend, or NULL if none found.
 */
const struct dongle_ops *dongle_detect(void)
{
	int i;

	scan_once();

	for (i = 0; i < g_plugin_cnt; i++) {
		const struct dongle_ops *ops = g_plugins[i].ops;

		if (!ops->probe)
			continue;
		if (ops->probe()) {
			fprintf(stderr, "[dongle] Auto-detected: %s\n", ops->name);
			return ops;
		}
	}

	fprintf(stderr, "[dongle] No dongle detected\n");
	return NULL;
}
