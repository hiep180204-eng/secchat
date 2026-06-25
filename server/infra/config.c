/*
 * infra/config.c — nạp cấu hình runtime tập trung (đọc từ biến môi trường).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "log.h"

/* Global singleton populated by config_load(). */
Config g_config;

/* ── helpers ─────────────────────────────────────────────────── */

static int env_int(const char *name, int def)
{
    const char *v = getenv(name);
    if (!v || !v[0]) return def;
    char *end = NULL;
    long  val = strtol(v, &end, 10);
    return (end && end != v) ? (int)val : def;
}

static void env_str(const char *name, char *dst, size_t dstsz,
                    const char *def)
{
    const char *v = getenv(name);
    if (v && v[0])
        strncpy(dst, v, dstsz - 1);
    else if (def)
        strncpy(dst, def, dstsz - 1);
    dst[dstsz - 1] = '\0';
}

/* ── public API ──────────────────────────────────────────────── */

void config_load(Config *out)
{
    /* Network */
    out->ws_port     = env_int("SECCHAT_PORT",        8888);
    out->http_port   = env_int("SECCHAT_HTTP_PORT",   8889);
    out->max_clients = env_int("SECCHAT_MAX_CLIENTS", 200);

    /* TLS */
    env_str("SECCHAT_TLS_CERT", out->tls_cert, sizeof(out->tls_cert),
            "/etc/ssl/chat.crt");
    env_str("SECCHAT_TLS_KEY",  out->tls_key,  sizeof(out->tls_key),
            "/etc/ssl/chat.key");

    /* Database */
    env_str("DB_HOST", out->db_host, sizeof(out->db_host), "db");
    out->db_port = env_int("DB_PORT", 3306);
    env_str("DB_NAME", out->db_name, sizeof(out->db_name), "chatdb");
    env_str("DB_USER", out->db_user, sizeof(out->db_user), "chatuser");
    env_str("DB_PASS", out->db_pass, sizeof(out->db_pass), "");

    /* Logging */
    out->log_json = env_int("SECCHAT_LOG_JSON", 0);
    env_str("SECCHAT_LOG_LEVEL", out->log_level, sizeof(out->log_level),
            "INFO");

    /* HTTP control plane */
    env_str("HTTP_METRICS_TOKEN", out->http_metrics_token,
            sizeof(out->http_metrics_token), "");

    /* Migrations */
    env_str("MIGRATIONS_DIR", out->migrations_dir, sizeof(out->migrations_dir),
            "/usr/local/share/chat_server/migrations");

    /* Copy to global singleton */
    g_config = *out;
}

void config_print(const Config *cfg)
{
    log_info("Config: ws_port=%d http_port=%d max_clients=%d",
             cfg->ws_port, cfg->http_port, cfg->max_clients);
    log_info("Config: tls_cert=%s tls_key=%s",
             cfg->tls_cert, cfg->tls_key);
    log_info("Config: db=%s@%s:%d/%s log_json=%d log_level=%s",
             cfg->db_user, cfg->db_host, cfg->db_port, cfg->db_name,
             cfg->log_json, cfg->log_level);
    log_info("Config: migrations_dir=%s", cfg->migrations_dir);
    log_info("Config: http_metrics_token=%s",
             cfg->http_metrics_token[0] ? "(set)" : "(open — no auth)");
}
