/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Dongle factory — run-time plugin loader.
 *
 * Backends are no longer linked in at build time.  Two ways to obtain one:
 *
 *   dongle_get(name)   loads <plugin dir>/<name>.so directly -- exactly one
 *                      file, no directory traversal.  <name> must be a plain
 *                      file name: [A-Za-z0-9._-], no '/', <= 64 chars.
 *   dongle_detect()    scans the plugin dir for *.so, dlopen()s each one,
 *                      checks its reported ABI version and picks the first
 *                      whose probe() succeeds.
 *
 * Either way the .so must report a matching ABI version, so dropping one
 * into the directory is still equivalent to "installing a dongle driver".
 *
 *   default dir : /oemdata/opt/optee/dongle/
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

#define DONGLE_DIR_DEFAULT	"/oemdata/opt/optee/dongle"
#define PLUGIN_MAX		8
#define PATH_MAX_LEN		512
#define BACKEND_NAME_MAX	64

/* ---- Loaded plugins ---- */
static struct {
	const struct dongle_ops *ops;
	void                    *dl;	/* dlopen handle (never closed) */
	char                     path[PATH_MAX_LEN];	/* as dlopen'd — dedup key */
} g_plugins[PLUGIN_MAX];
static int  g_plugin_cnt;
/*
 * Guards the DIRECTORY SCAN only — it does NOT mean "plugins are loaded".
 * dongle_get() loads a single file on demand and never sets this; a later
 * dongle_detect() must still scan.  Do not use it as a "loaded yet?" flag.
 */
static int  g_scanned;

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

/* Defined below scan_once(); declared here for load_plugin()'s re-sort */
static int plugin_cmp(const void *a, const void *b);

/*
 * Accept only plain file names.  This is a SECURITY boundary, not cosmetics:
 * the name is concatenated into "<dir>/<name>.so", so a '/' would let the
 * caller escape the plugin directory ("../../tmp/evil"), and it would also
 * give one file a second path spelling -- defeating the path dedup below
 * and loading the same plugin twice.
 */
static int valid_backend_name(const char *name)
{
	const char *p;
	size_t len;

	if (!name || !*name)
		return 0;

	len = strlen(name);
	if (len > BACKEND_NAME_MAX)
		return 0;

	/* "." / ".." and hidden files */
	if (name[0] == '.')
		return 0;

	for (p = name; *p; p++) {
		if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' ||
		    *p == '-')
			continue;
		return 0;
	}

	return 1;
}

/* Registry index loaded from this exact path, or -1 */
static int find_by_path(const char *path)
{
	int i;

	for (i = 0; i < g_plugin_cnt; i++) {
		if (strcmp(g_plugins[i].path, path) == 0)
			return i;
	}
	return -1;
}

/* Registry index whose plugin calls itself this name, or -1 */
static int find_by_name(const char *name)
{
	int i;

	for (i = 0; i < g_plugin_cnt; i++) {
		if (strcmp(g_plugins[i].ops->name, name) == 0)
			return i;
	}
	return -1;
}

/*
 * Failure hint: list what IS installed.  opendir() only -- we deliberately
 * do not dlopen anything here (that is the cost this change removes).
 */
static void hint_available(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	int found = 0;

	if (!d) {
		fprintf(stderr, "[dongle] plugin directory not found: %s\n", dir);
		return;
	}

	while ((e = readdir(d)) != NULL) {
		if (!has_suffix(e->d_name, ".so"))
			continue;
		if (!found)
			fprintf(stderr, "[dongle] installed plugins in %s:", dir);
		fprintf(stderr, " %s", e->d_name);
		found = 1;
	}
	closedir(d);

	if (found)
		fprintf(stderr, "\n");
	else
		fprintf(stderr, "[dongle] no *.so in %s\n", dir);
}

/*
 * Load one plugin and register it.
 *
 * Returns its ops table, or NULL on failure.  Every failure path is
 * non-fatal: a broken or incompatible plugin is reported and skipped.
 *
 * Loading a path that is already registered returns the existing entry --
 * it does NOT dlopen a second time or consume another slot.
 */
static const struct dongle_ops *load_plugin(const char *dir, const char *file)
{
	char path[PATH_MAX_LEN];
	void *dl;
	uint32_t (*abi_ver)(void);
	const struct dongle_ops *(*get_ops)(void);
	void (*set_dir)(const char *);
	const struct dongle_ops *ops;
	int idx;

	if (snprintf(path, sizeof(path), "%s/%s", dir, file) >= (int)sizeof(path)) {
		/* Don't print `path` here -- it is the truncated buffer */
		fprintf(stderr, "[dongle] path too long, skipping: %s/%s\n",
			dir, file);
		return NULL;
	}

	/* Already loaded from this exact file?  Reuse that entry. */
	idx = find_by_path(path);
	if (idx >= 0)
		return g_plugins[idx].ops;

	/*
	 * Checked AFTER the dedup above: a repeat load of an already-loaded
	 * plugin must not be refused just because the slot table is full.
	 */
	if (g_plugin_cnt >= PLUGIN_MAX) {
		fprintf(stderr, "[dongle] plugin limit (%d) reached, skipping %s\n",
			PLUGIN_MAX, path);
		return NULL;
	}

	/* RTLD_LOCAL: don't pollute the global symbol namespace */
	dl = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!dl) {
		fprintf(stderr, "[dongle] cannot load %s: %s\n", path, dlerror());
		return NULL;
	}

	/* Both entry points are mandatory */
	abi_ver = (uint32_t (*)(void))dlsym(dl, DONGLE_PLUGIN_SYM_ABI_VER);
	get_ops = (const struct dongle_ops *(*)(void))dlsym(dl,
						DONGLE_PLUGIN_SYM_GET_OPS);
	if (!abi_ver || !get_ops) {
		fprintf(stderr, "[dongle] %s is not a dongle plugin "
			"(missing %s / %s)\n", path,
			DONGLE_PLUGIN_SYM_ABI_VER, DONGLE_PLUGIN_SYM_GET_OPS);
		dlclose(dl);
		return NULL;
	}

	/* ABI guard: refuse mismatched plugins rather than crash later */
	if (abi_ver() != DONGLE_PLUGIN_ABI_VERSION) {
		fprintf(stderr, "[dongle] %s: ABI mismatch (plugin=%u, host=%u) "
			"— refusing to load\n", path,
			abi_ver(), DONGLE_PLUGIN_ABI_VERSION);
		dlclose(dl);
		return NULL;
	}

	/*
	 * Optional: tell the plugin where it lives (for companion key files).
	 * This is the plugin DIRECTORY, not the .so path -- dongle_dummy.c
	 * resolves <dir>/dummy.key from it.  Keep that contract; see the note
	 * next to DONGLE_PLUGIN_SYM_SET_DIR in dongle_ops.h.
	 */
	set_dir = (void (*)(const char *))dlsym(dl, DONGLE_PLUGIN_SYM_SET_DIR);
	if (set_dir)
		set_dir(dir);

	ops = get_ops();
	if (!ops || !ops->name || !ops->probe) {
		fprintf(stderr, "[dongle] %s: invalid ops table\n", path);
		dlclose(dl);
		return NULL;
	}

	g_plugins[g_plugin_cnt].ops = ops;
	g_plugins[g_plugin_cnt].dl  = dl;
	snprintf(g_plugins[g_plugin_cnt].path,
		 sizeof(g_plugins[g_plugin_cnt].path), "%s", path);
	g_plugin_cnt++;

	/*
	 * If a scan already sorted the table, appending would leave this entry
	 * at the tail and break dongle_detect()'s probe order.  Re-sort.
	 */
	if (g_scanned && g_plugin_cnt > 1)
		qsort(g_plugins, (size_t)g_plugin_cnt, sizeof(g_plugins[0]),
		      plugin_cmp);

	fprintf(stderr, "[dongle] loaded plugin: %s (%s)\n",
		ops->name, ops->key_type ? ops->key_type : "?");
	return ops;
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

	if (g_scanned)
		return;
	g_scanned = 1;

	d = opendir(dir);
	if (!d) {
		/* A missing directory simply means "no dongle drivers installed" */
		fprintf(stderr, "[dongle] no plugin directory: %s\n", dir);
		return;
	}

	while ((e = readdir(d)) != NULL) {
		if (!has_suffix(e->d_name, ".so"))
			continue;
		/* Return value ignored: one bad plugin must not stop the scan.
		 * Already-loaded files are skipped inside load_plugin(). */
		load_plugin(dir, e->d_name);
	}
	closedir(d);

	if (g_plugin_cnt > 1)
		qsort(g_plugins, (size_t)g_plugin_cnt, sizeof(g_plugins[0]),
		      plugin_cmp);
}

/*
 * Get a specific backend by name.
 *
 * Resolves <name> to <plugin dir>/<name>.so and loads exactly that one file
 * -- it does NOT scan the directory.  Returns NULL if the name is not a
 * plain file name, or the file is missing / broken / ABI-mismatched.
 *
 * <name> must match [A-Za-z0-9._-], must not start with '.', and must be at
 * most BACKEND_NAME_MAX chars.  Filesystem paths are deliberately rejected
 * (see valid_backend_name).
 */
const struct dongle_ops *dongle_get(const char *name)
{
	char file[BACKEND_NAME_MAX + 4];	/* "<name>.so" */
	char path[PATH_MAX_LEN];
	const char *dir;
	const struct dongle_ops *ops;
	int idx;

	if (!valid_backend_name(name)) {
		if (name && *name)
			fprintf(stderr, "[dongle] invalid backend name \"%s\": "
				"use [A-Za-z0-9._-], max %d chars, no '/'\n",
				name, BACKEND_NAME_MAX);
		return NULL;
	}

	dir = dongle_dir();

	if (snprintf(file, sizeof(file), "%s.so", name) >= (int)sizeof(file) ||
	    snprintf(path, sizeof(path), "%s/%s", dir, file) >= (int)sizeof(path)) {
		fprintf(stderr, "[dongle] backend path too long: %s/%s.so\n",
			dir, name);
		return NULL;
	}

	/* Already loaded from exactly this file -- by an earlier dongle_get(),
	 * or by a dongle_detect() scan.  Reuse it. */
	idx = find_by_path(path);
	if (idx >= 0)
		return g_plugins[idx].ops;

	/* Load that one file.  No directory traversal. */
	ops = load_plugin(dir, file);
	if (ops) {
		if (strcmp(ops->name, name) != 0)
			fprintf(stderr, "[dongle] warning: %s reports backend "
				"name \"%s\" (requested \"%s\") — using it, but "
				"--dongle %s will not resolve to this file\n",
				path, ops->name, name, ops->name);
		return ops;
	}

	/*
	 * Fall back to a self-reported match: a scan may have loaded this
	 * backend from a differently-named file.  Warn, but keep working.
	 */
	idx = find_by_name(name);
	if (idx >= 0) {
		fprintf(stderr, "[dongle] warning: backend \"%s\" resolved to the "
			"already-loaded %s, not %s\n",
			name, g_plugins[idx].path, path);
		return g_plugins[idx].ops;
	}

	fprintf(stderr, "[dongle] backend \"%s\" not available — no %s "
		"(pass the backend NAME without the .so suffix)\n", name, path);
	hint_available(dir);

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
