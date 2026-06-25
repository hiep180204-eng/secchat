#ifndef SECCHAT_INFRA_CONFIG_H
#define SECCHAT_INFRA_CONFIG_H

/*
 * infra/config.h — centralised runtime configuration
 *
 * All server parameters are read from environment variables.
 * Call config_load() once at startup; then read from g_config anywhere.
 *
 * Environment variables and their defaults:
 *
 *   SECCHAT_PORT          WebSocket server port           (default: 8888)
 *   SECCHAT_HTTP_PORT     HTTP control-plane port         (default: 8889)
 *   SECCHAT_MAX_CLIENTS   Maximum concurrent connections  (default: 200)
 *   SECCHAT_TLS_CERT      Path to TLS certificate PEM     (default: /etc/ssl/chat.crt)
 *   SECCHAT_TLS_KEY       Path to TLS private key PEM     (default: /etc/ssl/chat.key)
 *   SECCHAT_LOG_JSON      1 = JSON log format, 0 = plain  (default: 0)
 *   SECCHAT_LOG_LEVEL     DEBUG|INFO|WARN|ERROR           (default: INFO)
 *   HTTP_METRICS_TOKEN    Bearer token required for GET /metrics (default: "" = open)
 *
 *   MIGRATIONS_DIR        Path to SQL migration files     (default: /usr/local/share/chat_server/migrations)
 *
 *   DB_HOST               MySQL host                      (default: db)
 *   DB_PORT               MySQL port                      (default: 3306)
 *   DB_NAME               MySQL database name             (default: chatdb)
 *   DB_USER               MySQL user                      (default: chatuser)
 *   DB_PASS               MySQL password                  (default: "")
 */

typedef struct {
    /* Network */
    int  ws_port;          /* SECCHAT_PORT */
    int  http_port;        /* SECCHAT_HTTP_PORT */
    int  max_clients;      /* SECCHAT_MAX_CLIENTS */

    /* TLS */
    char tls_cert[256];    /* SECCHAT_TLS_CERT */
    char tls_key[256];     /* SECCHAT_TLS_KEY */

    /* Database */
    char db_host[128];     /* DB_HOST */
    int  db_port;          /* DB_PORT */
    char db_name[64];      /* DB_NAME */
    char db_user[64];      /* DB_USER */
    char db_pass[128];     /* DB_PASS */

    /* Logging */
    int  log_json;         /* SECCHAT_LOG_JSON */
    char log_level[16];    /* SECCHAT_LOG_LEVEL */

    /* HTTP control plane */
    char http_metrics_token[128]; /* HTTP_METRICS_TOKEN — Bearer token for /metrics; "" = open */

    /* Migrations */
    char migrations_dir[256]; /* MIGRATIONS_DIR */
} Config;

/* Populated once by config_load(); read-only thereafter. */
extern Config g_config;

/* Read all environment variables and populate *out (and g_config).
   Call once from main() before any other subsystem init. */
void config_load(Config *out);

/* Print a summary of the loaded config to stdout (masks DB_PASS). */
void config_print(const Config *cfg);

#endif /* SECCHAT_INFRA_CONFIG_H */
