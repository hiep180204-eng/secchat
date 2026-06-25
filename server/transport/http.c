/*
 * transport/http.c — control plane HTTP (TCP thuần, tách khỏi WebSocket).
 *
 * Endpoint:
 *   GET /healthz  → 200 "ok"
 *   GET /readyz   → 200 "ok" | 503 "db_unavailable"
 *   GET /metrics  → 200 <snapshot metrics dạng json>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <winsock2.h>
#  define CLOSE_SOCK(s) closesocket(s)
#  define SOCK_T        SOCKET
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <unistd.h>
#  include <pthread.h>
#  define CLOSE_SOCK(s) close(s)
#  define SOCK_T        int
#  define INVALID_SOCKET (-1)
#endif

#include "http.h"
#include "metrics.h"
#include "log.h"
#include "config.h"
#include "db_pool.h"

/* ── internal helpers ─────────────────────────────────────── */

#define HTTP_OK_HDR  \
    "HTTP/1.1 200 OK\r\n"         \
    "Content-Type: application/json\r\n" \
    "Connection: close\r\n"        \
    "Content-Length: "

#define HTTP_503_HDR \
    "HTTP/1.1 503 Service Unavailable\r\n" \
    "Content-Type: text/plain\r\n"          \
    "Connection: close\r\n"                 \
    "Content-Length: "

#define HTTP_404_HDR \
    "HTTP/1.1 404 Not Found\r\n"   \
    "Content-Type: text/plain\r\n" \
    "Connection: close\r\n"        \
    "Content-Length: 9\r\n\r\nNot Found"

#define HTTP_401_HDR \
    "HTTP/1.1 401 Unauthorized\r\n"              \
    "Content-Type: text/plain\r\n"               \
    "WWW-Authenticate: Bearer realm=\"metrics\"" \
    "\r\nConnection: close\r\n"                  \
    "Content-Length: 12\r\n\r\nUnauthorized"

/* Return 1 if the /metrics request passes the token check (or no token is
   configured), 0 if it should be rejected. */
static int check_metrics_auth(const char *req)
{
    const char *tok = g_config.http_metrics_token;
    if (!tok[0]) return 1;   /* no token configured — open access */

    /* Search for "Authorization: Bearer " header in raw request */
    const char *hdr = strstr(req, "Authorization: Bearer ");
    if (!hdr) return 0;
    hdr += 22; /* skip "Authorization: Bearer " */

    /* Compare up to newline / carriage-return */
    size_t tok_len = strlen(tok);
    return (strncmp(hdr, tok, tok_len) == 0 &&
            (hdr[tok_len] == '\r' || hdr[tok_len] == '\n' || hdr[tok_len] == '\0'));
}

static void send_text(SOCK_T fd, const char *hdr_prefix,
                      const char *body, size_t blen)
{
    char hdr[128];
    int hlen = snprintf(hdr, sizeof(hdr), "%s%zu\r\n\r\n",
                        hdr_prefix, blen);
    if (hlen > 0) send(fd, hdr, (int)hlen, 0);
    if (blen > 0) send(fd, body, (int)blen, 0);
}

/* ── request handler ──────────────────────────────────────── */

static void handle_request(SOCK_T fd)
{
    char req[1024] = {0};
    int  n = (int)recv(fd, req, sizeof(req) - 1, 0);
    if (n <= 0) return;

    /* Only care about the first line: "GET /path HTTP/1.x" */
    if (strncmp(req, "GET ", 4) != 0) {
        send(fd, HTTP_404_HDR, (int)strlen(HTTP_404_HDR), 0);
        return;
    }

    /* Extract path — ends at first space after method */
    char path[64] = {0};
    const char *ps = req + 4;
    const char *pe = strchr(ps, ' ');
    if (!pe) pe = ps + strlen(ps);
    size_t plen = (size_t)(pe - ps);
    if (plen > 63) plen = 63;
    memcpy(path, ps, plen);

    if (strcmp(path, "/healthz") == 0) {
        const char *body = "\"ok\"";
        send_text(fd, HTTP_OK_HDR, body, strlen(body));

    } else if (strcmp(path, "/readyz") == 0) {
        if (db_pool_ping_once()) {
            const char *body = "\"ok\"";
            send_text(fd, HTTP_OK_HDR, body, strlen(body));
        } else {
            const char *body = "\"db_unavailable\"";
            send_text(fd, HTTP_503_HDR, body, strlen(body));
        }

    } else if (strcmp(path, "/metrics") == 0) {
        if (!check_metrics_auth(req)) {
            send(fd, HTTP_401_HDR, (int)strlen(HTTP_401_HDR), 0);
            return;
        }
        char *snap = metrics_snapshot_json();
        if (snap) {
            send_text(fd, HTTP_OK_HDR, snap, strlen(snap));
            free(snap);
        } else {
            const char *err = "\"metrics_unavailable\"";
            send_text(fd, HTTP_503_HDR, err, strlen(err));
        }

    } else {
        send(fd, HTTP_404_HDR, (int)strlen(HTTP_404_HDR), 0);
    }
}

/* ── listener thread ──────────────────────────────────────── */

typedef struct { int port; } HttpArg;

#ifdef _WIN32
static DWORD WINAPI http_thread(LPVOID arg)
#else
static void *http_thread(void *arg)
#endif
{
    HttpArg *ha   = (HttpArg *)arg;
    int      port = ha->port;
    free(ha);

    SOCK_T srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) {
        log_error("HTTP control plane: socket() failed");
        return NULL;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((unsigned short)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("HTTP control plane: bind() failed on port %d", port);
        CLOSE_SOCK(srv);
        return NULL;
    }
    listen(srv, 8);
    log_info("HTTP control plane listening on port %d (/healthz /readyz /metrics)", port);

    while (1) {
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);
        SOCK_T cfd = accept(srv, (struct sockaddr *)&cli, &cli_len);
        if (cfd == INVALID_SOCKET) continue;
        handle_request(cfd);
        CLOSE_SOCK(cfd);
    }

    CLOSE_SOCK(srv);
    return NULL;
}

/* ── public API ────────────────────────────────────────────── */

int http_server_start(int port)
{
    HttpArg *ha = (HttpArg *)malloc(sizeof(HttpArg));
    if (!ha) return 0;
    ha->port = port;

#ifdef _WIN32
    HANDLE h = CreateThread(NULL, 0, http_thread, ha, 0, NULL);
    if (!h) { free(ha); return 0; }
    CloseHandle(h);
#else
    pthread_t tid;
    if (pthread_create(&tid, NULL, http_thread, ha) != 0) {
        free(ha); return 0;
    }
    pthread_detach(tid);
#endif
    return 1;
}
