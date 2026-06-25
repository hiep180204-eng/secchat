/*
 * server/main.c — điểm vào của server SecChat.
 *
 * Khởi tạo cấu hình, log, metrics, pool DB (chạy migration), rồi mở HTTP control
 * plane và vòng lặp chấp nhận kết nối WebSocket/TLS. Mỗi client được cấp một
 * slot; lệnh JSON nhận được định tuyến tới các service tương ứng.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32
  #include <winsock2.h>
  #pragma comment(lib,"ws2_32.lib")
  #define CLOSE_SOCK(s) closesocket(s)
  typedef int socklen_t;
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <pthread.h>
  #define INVALID_SOCKET (-1)
  #define CLOSE_SOCK(s)  close(s)
  #define SOCKET_T       int
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "log.h"
#include "ws.h"
#include "db_lifecycle.h"
#include "clients.h"
#include "json_helpers.h"
#include "crypto.h"
#include "metrics.h"
#include "config.h"
#include "http.h"
#include "auth.h"
#include "friends.h"
#include "profile.h"
#include "presence.h"
#include "chat.h"
#include "groups.h"
#include "keys.h"
#include "blocking.h"
#include "notifications.h"
#include "ratelimit.h"
#include "db_pool.h"

#define BUF_SIZE         8192
#define MAX_MSG_BUF      (4 * 1024 * 1024)    /* enough for 1 MiB E2EE file payloads */

/* PORT and TLS paths are read from g_config at runtime; fallback defaults live
 * in config.c. */
#define TLS_CERT_FILE    g_config.tls_cert
#define TLS_KEY_FILE     g_config.tls_key

/* Unauthenticated connections that don't login within this window are closed */
#define AUTH_TIMEOUT_SECS  30

/* ── global SSL context ──────────────────────────────────── */
static SSL_CTX *g_ssl_ctx = NULL;

static SSL_CTX *create_ssl_ctx(void)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "FATAL: SSL_CTX_new failed\n");
        exit(1);
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, TLS_CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "FATAL: Cannot load TLS certificate %s\n", TLS_CERT_FILE);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, TLS_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "FATAL: Cannot load TLS private key %s\n", TLS_KEY_FILE);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "FATAL: TLS certificate and private key do not match\n");
        exit(1);
    }
    return ctx;
}

/* ── per-client thread ────────────────────────────────────── */

typedef struct { SOCKET_T fd; int idx; } ThreadArg;

/* Returns 1 if the slot is authenticated, sends an error if not. */
static int require_auth(int idx)
{
    if (clients_get_uid(idx) <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not authenticated\"}");
        return 0;
    }
    return 1;
}

static void dispatch(int idx, const char *buf)
{
    char type[32] = {0};
    jget(buf, "type", type, sizeof(type));

    /* ---- unauthenticated ---- */
    if (strcmp(type, "auth") == 0) {
        handle_auth(idx, buf);
        return;
    }
    if (strcmp(type, "register") == 0) {
        handle_register(idx, buf);
        return;
    }

    /* ---- everything else requires login ---- */
    if (!require_auth(idx)) return;

    /* ---- change_password (requires auth) ---- */
    if (strcmp(type, "change_password") == 0) {
        handle_change_password(idx, buf);
        return;
    }

    /* ---- friends & social graph ---- */
    if (friends_dispatch(idx, type, buf)) return;

    /* ---- profile management ---- */
    if (profile_dispatch(idx, type, buf)) return;

    /* ---- presence & privacy settings ---- */
    if (presence_dispatch(idx, type, buf)) return;

    /* ---- messaging (send/history/inbox/DM/edit/delete/typing/reactions/mention) ---- */
    if (chat_dispatch(idx, type, buf)) return;

    /* ---- group management (create/add/disband/leave/kick/roles/info) ---- */
    if (groups_dispatch(idx, type, buf)) return;

    /* ---- key management (upload/rotate/conv keys/safety numbers) ---- */
    if (keys_dispatch(idx, type, buf)) return;

    /* ---- blocking ---- */
    if (blocking_dispatch(idx, type, buf)) return;

    if (strcmp(type, "logout") == 0) {
        /* Graceful logout — clear auth identity and broadcast offline immediately.
           After clients_logout_user(), this slot's user_id is -1, so when the
           connection closes and clients_remove() runs, presence broadcast is skipped. */
        int uid = clients_logout_user(idx);
        clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Logged out\"}");
        log_info("User uid=%d logged out gracefully", uid);

    } else {
        log_warn("Unknown message type: '%s'", type);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Unsupported command\"}");
    }
}

/* ── Disappearing-message sweep thread ──────────────────────── */
#ifdef _WIN32
static DWORD WINAPI disappear_thread(LPVOID arg)
#else
static void *disappear_thread(void *arg)
#endif
{
    (void)arg;
    while (1) {
#ifdef _WIN32
        Sleep(60000);
#else
        sleep(60);
#endif
        MYSQL *conn = db_pool_acquire();
        if (conn) {
            /* Soft-delete only messages sent after the timer was enabled.
             * Older history stays visible so enabling a timer cannot wipe an
             * existing conversation by surprise. */
            mysql_query(conn,
                "UPDATE messages m"
                " JOIN conversations c ON m.conversation_id = c.id"
                " SET m.deleted_at = NOW()"
                " WHERE c.disappear_after_secs IS NOT NULL"
                "   AND c.disappear_enabled_at IS NOT NULL"
                "   AND m.deleted_at IS NULL"
                "   AND m.sent_at >= c.disappear_enabled_at"
                "   AND TIMESTAMPDIFF(SECOND, m.sent_at, NOW())"
                "       > c.disappear_after_secs");
            db_pool_release(conn);
        }
    }
    return NULL;
}

/* ── Janitor thread — evict unauthenticated connections ─────── */
#ifdef _WIN32
static DWORD WINAPI janitor_thread(LPVOID arg)
#else
static void *janitor_thread(void *arg)
#endif
{
    (void)arg;
    while (1) {
#ifdef _WIN32
        Sleep(10000);
#else
        sleep(10);
#endif
        clients_timeout_check(AUTH_TIMEOUT_SECS);
    }
    return NULL;
}

#ifdef _WIN32
static DWORD WINAPI client_thread(LPVOID arg)
#else
static void *client_thread(void *arg)
#endif
{
    ThreadArg *ta  = (ThreadArg *)arg;
    SOCKET_T   fd  = ta->fd;
    int        idx = ta->idx;
    free(ta);

    /* ---- TLS handshake ---- */
    SSL *ssl = SSL_new(g_ssl_ctx);
    if (!ssl) {
        log_warn("SSL_new failed on slot %d", idx);
        CLOSE_SOCK(fd);
        clients_remove(idx);
        return NULL;
    }
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) <= 0) {
        log_warn("TLS handshake failed on slot %d", idx);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        CLOSE_SOCK(fd);
        clients_remove(idx);
        return NULL;
    }
    clients_set_ssl(idx, ssl);

    /* ---- WebSocket handshake ---- */
    char http_buf[4096] = {0};
    int  n = SSL_read(ssl, http_buf, sizeof(http_buf) - 1);
    if (n <= 0 || !ws_handshake(ssl, http_buf)) {
        log_warn("WS handshake failed on slot %d", idx);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        CLOSE_SOCK(fd);
        clients_remove(idx);
        return NULL;
    }
    clients_set_ready(idx);
    log_info("Client connected (slot=%d, TLS=%s)",
             idx, SSL_get_version(ssl));

    /* ---- receive loop ---- */
    char *buf = (char *)malloc(MAX_MSG_BUF);
    if (!buf) goto done;
    while (1) {
        int r = ws_recv(ssl, buf, MAX_MSG_BUF);
        if (r < -1) {
            /* Oversized frame: log once and close this connection. */
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Message too large\"}");
            break;
        }
        if (r < 0) break;
        if (r == 0) continue;   /* ping handled inside ws_recv */
        dispatch(idx, buf);
    }
    free(buf);

done:
    log_info("Client disconnected (slot=%d, uid=%d)", idx, clients_get_uid(idx));
    SSL_shutdown(ssl);
    SSL_free(ssl);
    CLOSE_SOCK(fd);
    clients_remove(idx);
    return NULL;
}

/* ── main ─────────────────────────────────────────────────── */

int main(void)
{
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    /* ---- load runtime config from environment ---- */
    Config cfg;
    config_load(&cfg);
    config_print(&cfg);

    /* ---- OpenSSL init ---- */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    g_ssl_ctx = create_ssl_ctx();
    log_info("TLS initialized (cert=%s)", TLS_CERT_FILE);

    if (!db_connect()) {
        fprintf(stderr, "FATAL: could not connect to MySQL\n");
        return 1;
    }
    clients_init();
    metrics_init();
    auth_init();
    ratelimit_init();

    /* Start HTTP control-plane (/healthz /readyz /metrics) */
    if (!http_server_start(g_config.http_port)) {
        log_warn("HTTP control plane failed to start on port %d",
                 g_config.http_port);
    }

    /* Start janitor thread for pre-auth timeout enforcement */
#ifdef _WIN32
    {
        HANDLE jh = CreateThread(NULL, 0, janitor_thread, NULL, 0, NULL);
        if (jh) CloseHandle(jh);
    }
#else
    {
        pthread_t jtid;
        pthread_create(&jtid, NULL, janitor_thread, NULL);
        pthread_detach(jtid);
    }
#endif

    /* Start disappearing-message sweep thread */
#ifdef _WIN32
    {
        HANDLE dh = CreateThread(NULL, 0, disappear_thread, NULL, 0, NULL);
        if (dh) CloseHandle(dh);
    }
#else
    {
        pthread_t dtid;
        pthread_create(&dtid, NULL, disappear_thread, NULL);
        pthread_detach(dtid);
    }
#endif

    SOCKET_T srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((unsigned short)g_config.ws_port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, SOMAXCONN);
    log_info("SecChat server listening on port %d (TLS, max %d clients)",
             g_config.ws_port, g_config.max_clients);

    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        SOCKET_T  cli_fd  = accept(srv, (struct sockaddr *)&cli_addr, &cli_len);
        if (cli_fd == INVALID_SOCKET) continue;

        int idx = clients_add(cli_fd);
        if (idx < 0) {
            log_warn("Server full — rejecting connection from %s",
                     inet_ntoa(cli_addr.sin_addr));
            metrics_conn_rejected();
            CLOSE_SOCK(cli_fd);
            continue;
        }
        /* Store remote IP for rate limiting */
        clients_set_ip(idx, inet_ntoa(cli_addr.sin_addr));

        ThreadArg *ta = (ThreadArg *)malloc(sizeof(ThreadArg));
        ta->fd  = cli_fd;
        ta->idx = idx;

#ifdef _WIN32
        HANDLE h = CreateThread(NULL, 0, client_thread, ta, 0, NULL);
        if (h) CloseHandle(h);
#else
        pthread_t tid;
        pthread_create(&tid, NULL, client_thread, ta);
        pthread_detach(tid);
#endif
    }

    SSL_CTX_free(g_ssl_ctx);
    db_close();
    metrics_stop();
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
