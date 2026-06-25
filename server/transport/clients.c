/*
 * transport/clients.c — bảng các kết nối client (slot) và phát sự kiện.
 *
 * Mỗi kết nối chiếm một slot giữ fd/TLS/uid/username. Cung cấp: gửi tới một slot,
 * gửi tới uid, broadcast theo hội thoại, và quản lý presence online/offline.
 * Chat state E2EE hiện là đơn thiết bị nên login mới thay thế các phiên cũ
 * của cùng uid.
 */
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#define CLOSE_SOCK(s) closesocket(s)
#else
#include <unistd.h>
#define CLOSE_SOCK(s) close(s)
#endif

#include "clients.h"
#include "ws.h"
#include "metrics.h"
#include "conversation_repo.h"
#include "presence.h"

/* ── globals ──────────────────────────────────────────────── */
static Client g_clients[MAX_CLIENTS];

#ifdef _WIN32
static CRITICAL_SECTION g_mtx;
#define LOCK()   EnterCriticalSection(&g_mtx)
#define UNLOCK() LeaveCriticalSection(&g_mtx)
#else
#include <pthread.h>
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
#define LOCK()   pthread_mutex_lock(&g_mtx)
#define UNLOCK() pthread_mutex_unlock(&g_mtx)
#endif

/* ── public ───────────────────────────────────────────────── */

void clients_init(void)
{
#ifdef _WIN32
    InitializeCriticalSection(&g_mtx);
#endif
    memset(g_clients, 0, sizeof(g_clients));
    for (int i = 0; i < MAX_CLIENTS; i++) {
        g_clients[i].fd  = INVALID_SOCKET;
        g_clients[i].ssl = NULL;
    }
}

int clients_add(SOCKET_T fd)
{
    LOCK();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_clients[i].active) {
            g_clients[i].fd           = fd;
            g_clients[i].ssl          = NULL;
            g_clients[i].active       = 1;
            g_clients[i].ws_ready     = 0;
            g_clients[i].username[0]  = '\0';
            g_clients[i].user_id      = -1;
            g_clients[i].ip[0]        = '\0';
            g_clients[i].connected_at = time(NULL);
            g_clients[i].last_search  = 0;
            UNLOCK();
            metrics_conn_accepted_and_opened();
            return i;
        }
    }
    UNLOCK();
    return -1;
}

/* ── Step 1: Only broadcast offline if no other session exists for this uid ── */
void clients_remove(int idx)
{
    LOCK();
    if (idx < 0 || idx >= MAX_CLIENTS || !g_clients[idx].active) {
        UNLOCK();
        return;
    }
    int uid = g_clients[idx].user_id;
    g_clients[idx].active   = 0;
    g_clients[idx].ws_ready = 0;
    g_clients[idx].ssl      = NULL;
    g_clients[idx].username[0] = '\0';
    g_clients[idx].user_id  = -1;

    /* Only set offline if no other active session for this user. */
    int still_active = 0;
    if (uid > 0) {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (g_clients[i].active && g_clients[i].user_id == uid) {
                still_active = 1;
                break;
            }
        }
    }
    UNLOCK();

    if (uid > 0 && !still_active) {
        presence_broadcast_offline(uid);
    }
    metrics_conn_closed();
}

/* ── Step 3: Graceful logout ── */
int clients_logout_user(int idx)
{
    int still_active = 0;
    LOCK();
    if (idx < 0 || idx >= MAX_CLIENTS || !g_clients[idx].active) {
        UNLOCK();
        return -1;
    }
    int uid = g_clients[idx].user_id;
    g_clients[idx].user_id     = -1;
    g_clients[idx].username[0] = '\0';
    if (uid > 0) {
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (i == idx) continue;
            if (g_clients[i].active && g_clients[i].user_id == uid) {
                still_active = 1;
                break;
            }
        }
    }
    UNLOCK();

    if (uid > 0 && !still_active)
        presence_broadcast_offline(uid);

    return uid;
}

void clients_set_ready(int idx)
{
    LOCK();
    if (idx >= 0 && idx < MAX_CLIENTS)
        g_clients[idx].ws_ready = 1;
    UNLOCK();
}

void clients_set_ssl(int idx, SSL *ssl)
{
    LOCK();
    if (idx >= 0 && idx < MAX_CLIENTS)
        g_clients[idx].ssl = ssl;
    UNLOCK();
}

void clients_send(int idx, const char *json)
{
    LOCK();
    if (idx >= 0 && idx < MAX_CLIENTS
        && g_clients[idx].active
        && g_clients[idx].ws_ready
        && g_clients[idx].ssl)
    {
        SSL *ssl = g_clients[idx].ssl;
        UNLOCK();
        ws_send(ssl, json);
        return;
    }
    UNLOCK();
}

void clients_send_to_uid(int target_uid, const char *json)
{
    /* Collect all active sessions for this uid while locked, then send outside
       the lock so ws_send (blocking I/O) never holds the global mutex. */
    SSL *targets[MAX_CLIENTS];
    int count = 0;
    LOCK();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active && g_clients[i].ws_ready
            && g_clients[i].user_id == target_uid && g_clients[i].ssl)
        {
            targets[count++] = g_clients[i].ssl;
        }
    }
    UNLOCK();
    for (int i = 0; i < count; i++)
        ws_send(targets[i], json);
}

int clients_replace_other_sessions(int uid, int keep_idx)
{
    SSL *targets[MAX_CLIENTS];
    int count = 0;

    if (uid <= 0)
        return 0;

    LOCK();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (i == keep_idx)
            continue;
        if (g_clients[i].active && g_clients[i].ws_ready
            && g_clients[i].user_id == uid && g_clients[i].ssl)
        {
            targets[count++] = g_clients[i].ssl;
            g_clients[i].user_id = -1;
            g_clients[i].username[0] = '\0';
        }
    }
    UNLOCK();

    for (int i = 0; i < count; i++) {
        ws_send(targets[i],
                "{\"type\":\"session_replaced\","
                "\"msg\":\"This account signed in on another device.\"}");
    }
    return count;
}

int clients_get_uid(int idx)
{
    LOCK();
    int uid = (idx >= 0 && idx < MAX_CLIENTS) ? g_clients[idx].user_id : -1;
    UNLOCK();
    return uid;
}

void clients_get_username(int idx, char out[USERNAME_LEN])
{
    LOCK();
    if (idx >= 0 && idx < MAX_CLIENTS)
        strncpy(out, g_clients[idx].username, USERNAME_LEN - 1);
    else
        out[0] = '\0';
    out[USERNAME_LEN - 1] = '\0';   /* L-3 */
    UNLOCK();
}

void clients_broadcast_conv(long long conv_id, const char *json)
{
    /* L-2: Dynamic allocation scales with MAX_CLIENTS. */
    int *uids = (int *)malloc(MAX_CLIENTS * sizeof(int));
    if (!uids) return;
    int count = conv_get_members(conv_id, uids, MAX_CLIENTS);
    for (int i = 0; i < count; i++)
        clients_send_to_uid(uids[i], json);
    free(uids);
}

Client *clients_slot(int idx)
{
    return (idx >= 0 && idx < MAX_CLIENTS) ? &g_clients[idx] : NULL;
}

/* IP accessors */
void clients_set_ip(int idx, const char *ip)
{
    if (!ip) return;
    LOCK();
    if (idx >= 0 && idx < MAX_CLIENTS) {
        strncpy(g_clients[idx].ip, ip, IP_LEN - 1);
        g_clients[idx].ip[IP_LEN - 1] = '\0';    /* L-3 */
    }
    UNLOCK();
}

void clients_get_ip(int idx, char out[IP_LEN])
{
    LOCK();
    if (idx >= 0 && idx < MAX_CLIENTS)
        strncpy(out, g_clients[idx].ip, IP_LEN - 1);
    else
        out[0] = '\0';
    out[IP_LEN - 1] = '\0';   /* L-3 */
    UNLOCK();
}

/* Per-connection search rate limit */
int clients_check_search_rate(int idx)
{
    time_t now = time(NULL);
    LOCK();
    if (idx < 0 || idx >= MAX_CLIENTS || !g_clients[idx].active) {
        UNLOCK();
        return 0;
    }
    if (now - g_clients[idx].last_search < 1) {
        UNLOCK();
        return 0;
    }
    g_clients[idx].last_search = now;
    UNLOCK();
    return 1;
}

/* ── Online presence check ───────────────────────────────── */
int clients_is_online(int uid)
{
    if (uid <= 0) return 0;
    LOCK();
    int found = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active && g_clients[i].ws_ready && g_clients[i].user_id == uid) {
            found = 1;
            break;
        }
    }
    UNLOCK();
    return found;
}

/* Pre-auth timeout enforcement */
void clients_timeout_check(int timeout_secs)
{
    time_t now = time(NULL);

    SOCKET_T to_close[MAX_CLIENTS];
    int      count = 0;

    LOCK();
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active
            && g_clients[i].user_id <= 0
            && g_clients[i].connected_at > 0
            && now - g_clients[i].connected_at > timeout_secs)
        {
            to_close[count++] = g_clients[i].fd;
            g_clients[i].connected_at = 0;
        }
    }
    UNLOCK();

    for (int i = 0; i < count; i++) {
        metrics_preauth_timeout();
        if (to_close[i] != INVALID_SOCKET)
            CLOSE_SOCK(to_close[i]);
    }
}
