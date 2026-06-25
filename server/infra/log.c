/*
 * infra/log.c — ghi log có cấu trúc
 *
 * When SECCHAT_LOG_JSON=1 emits one JSON object per line:
 *   {"ts":"2026-05-03T08:33:11Z","level":"INFO","msg":"Server started"}
 *
 * Otherwise emits human-readable output:
 *   [08:33:11] INFO   Server started
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifndef _WIN32
#include <pthread.h>
static pthread_mutex_t g_log_mtx = PTHREAD_MUTEX_INITIALIZER;
#define LOG_LOCK()   pthread_mutex_lock(&g_log_mtx)
#define LOG_UNLOCK() pthread_mutex_unlock(&g_log_mtx)
#else
#include <windows.h>
static CRITICAL_SECTION g_log_cs;
static int g_log_cs_init = 0;
#define LOG_LOCK()   do { if (!g_log_cs_init) { \
    InitializeCriticalSection(&g_log_cs); g_log_cs_init=1; } \
    EnterCriticalSection(&g_log_cs); } while(0)
#define LOG_UNLOCK() LeaveCriticalSection(&g_log_cs)
#endif

#include "log.h"

/* ── Cached env values (read once, then locked) ─────────────── */
static int  g_json_mode  = -1;   /* -1 = not yet read */
static int  g_min_level  = 1;    /* 0=DEBUG 1=INFO 2=WARN 3=ERROR */

static int level_int(const char *lvl)
{
    /* lvl has trailing space padding, e.g. "INFO " */
    if (strncmp(lvl, "DEBU", 4) == 0) return 0;
    if (strncmp(lvl, "INFO", 4) == 0) return 1;
    if (strncmp(lvl, "WARN", 4) == 0) return 2;
    if (strncmp(lvl, "ERRO", 4) == 0) return 3;
    return 1;
}

static void init_once(void)
{
    if (g_json_mode >= 0) return;   /* already initialised */

    const char *json_env  = getenv("SECCHAT_LOG_JSON");
    const char *level_env = getenv("SECCHAT_LOG_LEVEL");

    g_json_mode = (json_env && json_env[0] == '1') ? 1 : 0;

    if (level_env && level_env[0]) {
        if      (strncasecmp(level_env, "DEBUG", 5) == 0) g_min_level = 0;
        else if (strncasecmp(level_env, "INFO",  4) == 0) g_min_level = 1;
        else if (strncasecmp(level_env, "WARN",  4) == 0) g_min_level = 2;
        else if (strncasecmp(level_env, "ERROR", 5) == 0) g_min_level = 3;
    }
}

/* ── JSON string escaping (inline, no alloc) ────────────────── */
static void write_json_escaped(FILE *f, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if      (c == '"')  fputs("\\\"", f);
        else if (c == '\\') fputs("\\\\", f);
        else if (c == '\n') fputs("\\n",  f);
        else if (c == '\r') fputs("\\r",  f);
        else if (c == '\t') fputs("\\t",  f);
        else if (c < 0x20)  fprintf(f, "\\u%04x", c);
        else                fputc(c, f);
    }
}

/* ── Public API ─────────────────────────────────────────────── */

void log_write(const char *level, const char *fmt, ...)
{
    LOG_LOCK();
    init_once();

    /* Filter by minimum level */
    if (level_int(level) < g_min_level) {
        LOG_UNLOCK();
        return;
    }

    /* Format the message into a local buffer */
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* Timestamp */
    time_t t = time(NULL);
    struct tm tm_buf;
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
    struct tm *tm_p = &tm_buf;
#else
    struct tm *tm_p = gmtime_r(&t, &tm_buf);
    if (!tm_p) tm_p = &tm_buf;
#endif

    if (g_json_mode) {
        /* ISO-8601 UTC timestamp */
        char ts[24];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm_p);

        /* Strip trailing space from level label */
        char lvl_clean[8] = {0};
        strncpy(lvl_clean, level, sizeof(lvl_clean) - 1);
        char *sp = strchr(lvl_clean, ' ');
        if (sp) *sp = '\0';

        fprintf(stdout, "{\"ts\":\"%s\",\"level\":\"%s\",\"msg\":\"", ts, lvl_clean);
        write_json_escaped(stdout, msg);
        fputs("\"}\n", stdout);
    } else {
        char ts[10];
        strftime(ts, sizeof(ts), "%H:%M:%S", tm_p);
        fprintf(stdout, "[%s] %s  %s\n", ts, level, msg);
    }

    fflush(stdout);
    LOG_UNLOCK();
}
