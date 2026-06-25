/*
 * services/friends.c — kết bạn: gửi/chấp nhận/từ chối lời mời, danh sách bạn,
 * tìm kiếm người dùng. Quan hệ bạn bè là điều kiện cho nhiều thao tác (DM,
 * claim KeyPackage, xem hồ sơ theo quyền riêng tư).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clients.h"
#include "json_helpers.h"
#include "friends.h"
#include "friendship_repo.h"
#include "notification_repo.h"
#include "user_repo.h"
#include "metrics.h"

/* ── handlers ────────────────────────────────────────────────────────────── */

static void handle_get_friends(int idx)
{
    int my_uid = clients_get_uid(idx);
    FriendRecord friends[200];
    int n = friendship_list_for_user(my_uid, friends, 200);

    /* ~120 bytes per entry, plus wrapper */
    size_t buf_sz = 64 + (size_t)n * 192;
    char *buf = (char *)malloc(buf_sz);
    if (!buf) return;

    int pos = snprintf(buf, buf_sz, "{\"type\":\"friends_list\",\"friends\":[");
    for (int i = 0; i < n; i++) {
        char eu[130], ed[210];
        json_esc(friends[i].username,     eu, sizeof(eu));
        json_esc(friends[i].display_name, ed, sizeof(ed));
        if (i > 0) pos += snprintf(buf + pos, buf_sz - pos, ",");
        pos += snprintf(buf + pos, buf_sz - pos,
                        "{\"id\":%d,\"username\":\"%s\","
                        "\"display_name\":\"%s\",\"status\":\"%s\","
                        "\"last_seen\":\"%s\"}",
                        friends[i].id, eu, ed, friends[i].status,
                        friends[i].last_seen);
    }
    snprintf(buf + pos, buf_sz - pos, "]}");
    clients_send(idx, buf);
    free(buf);
}

static void handle_get_requests(int idx)
{
    int my_uid = clients_get_uid(idx);
    FriendRequestRecord reqs[100];
    int n = friendship_list_pending(my_uid, reqs, 100);

    size_t buf_sz = 64 + (size_t)n * 160;
    char *buf = (char *)malloc(buf_sz);
    if (!buf) return;

    int pos = snprintf(buf, buf_sz, "{\"type\":\"friend_requests\",\"requests\":[");
    for (int i = 0; i < n; i++) {
        char eu[130], ed[210];
        json_esc(reqs[i].username,     eu, sizeof(eu));
        json_esc(reqs[i].display_name, ed, sizeof(ed));
        if (i > 0) pos += snprintf(buf + pos, buf_sz - pos, ",");
        pos += snprintf(buf + pos, buf_sz - pos,
                        "{\"request_id\":%lld,\"user_id\":%d,"
                        "\"username\":\"%s\",\"display_name\":\"%s\","
                        "\"requested_at\":\"%s\"}",
                        reqs[i].request_id, reqs[i].user_id,
                        eu, ed, reqs[i].requested_at);
    }
    snprintf(buf + pos, buf_sz - pos, "]}");
    clients_send(idx, buf);
    free(buf);
}

static void handle_friend_request(int idx, int target_id)
{
    int my_uid = clients_get_uid(idx);
    if (my_uid == target_id) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Cannot friend yourself\"}");
        return;
    }
    char existing_status[32] = {0};
    int existing_requester = 0;
    if (friendship_get_status(my_uid, target_id, existing_status,
                              sizeof(existing_status), &existing_requester)) {
        if (strcmp(existing_status, "accepted") == 0) {
            clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Already friends\"}");
            return;
        }
        if (strcmp(existing_status, "pending") == 0) {
            clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Friend request sent\"}");
            (void)existing_requester;
            return;
        } else {
            clients_send(idx,
                "{\"type\":\"error\",\"msg\":\"Friend request is not available\"}");
            return;
        }
    } else if (!friendship_create_pending(my_uid, target_id, my_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to send request\"}");
        return;
    }
    clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Friend request sent\"}");

    char uname[USERNAME_LEN];
    clients_get_username(idx, uname);
    char notif[512];
    char eu[130];
    json_esc(uname, eu, sizeof(eu));
    snprintf(notif, sizeof(notif),
             "{\"type\":\"friend_request_received\",\"from\":\"%s\",\"from_id\":%d}",
             eu, my_uid);
    if (clients_is_online(target_id))
        clients_send_to_uid(target_id, notif);
    else
        notif_enqueue(target_id, "friend_request_received", notif);
}

static void handle_friend_accept(int idx, int requester_uid)
{
    int my_uid = clients_get_uid(idx);
    if (!friendship_accept(my_uid, requester_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to accept\"}");
        return;
    }
    clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Friend request accepted\"}");

    char uname[USERNAME_LEN];
    clients_get_username(idx, uname);
    char eu[130], notif[512];
    json_esc(uname, eu, sizeof(eu));
    snprintf(notif, sizeof(notif),
             "{\"type\":\"friend_accepted\",\"by\":\"%s\",\"by_id\":%d}",
             eu, my_uid);
    if (clients_is_online(requester_uid))
        clients_send_to_uid(requester_uid, notif);
    else
        notif_enqueue(requester_uid, "friend_accepted", notif);
}

static void handle_friend_remove(int idx, int other_id)
{
    int my_uid = clients_get_uid(idx);
    friendship_delete(my_uid, other_id);
    clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Removed\"}");
    clients_send_to_uid(other_id,
        "{\"type\":\"friend_removed\",\"msg\":\"removed\"}");
}

static void handle_search_user(int idx, const char *query)
{
    if (!query || query[0] == '\0') {
        clients_send(idx, "{\"type\":\"search_result\",\"users\":[]}");
        return;
    }
    if (!clients_check_search_rate(idx)) {
        metrics_search_ratelimited();
        clients_send(idx, "{\"type\":\"search_result\",\"users\":[]}");
        return;
    }
    metrics_search_ok();

    int my_uid = clients_get_uid(idx);
    UserRecord results[20];
    int n = user_repo_search(query, my_uid, results, 20);

    size_t buf_sz = 64 + (size_t)n * 128;
    char *buf = (char *)malloc(buf_sz);
    if (!buf) return;

    int pos = snprintf(buf, buf_sz, "{\"type\":\"search_result\",\"users\":[");
    for (int i = 0; i < n; i++) {
        char eu[130], ed[215];
        json_esc(results[i].username,     eu, sizeof(eu));
        json_esc(results[i].display_name, ed, sizeof(ed));
        if (i > 0) pos += snprintf(buf + pos, buf_sz - pos, ",");
        pos += snprintf(buf + pos, buf_sz - pos,
                        "{\"id\":%d,\"username\":\"%s\","
                        "\"display_name\":\"%s\",\"status\":\"%s\"}",
                        results[i].id, eu, ed, results[i].status);
    }
    snprintf(buf + pos, buf_sz - pos, "]}");
    clients_send(idx, buf);
    free(buf);
}

/* ── dispatcher ──────────────────────────────────────────────────────────── */

int friends_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "get_friends") == 0) {
        handle_get_friends(idx);
        return 1;
    }
    if (strcmp(type, "get_requests") == 0) {
        handle_get_requests(idx);
        return 1;
    }
    if (strcmp(type, "friend_request") == 0) {
        int target_id = 0;
        if (!jget_int(buf, "target_id", &target_id) || target_id <= 0) {
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid target_id\"}");
            return 1;
        }
        handle_friend_request(idx, target_id);
        return 1;
    }
    if (strcmp(type, "friend_accept") == 0) {
        int requester_id = 0;
        if (!jget_int(buf, "requester_id", &requester_id) || requester_id <= 0) {
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid requester_id\"}");
            return 1;
        }
        handle_friend_accept(idx, requester_id);
        return 1;
    }
    if (strcmp(type, "friend_reject") == 0) {
        int other_id = 0;
        if (!jget_int(buf, "other_id", &other_id) || other_id <= 0) {
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid other_id\"}");
            return 1;
        }
        handle_friend_remove(idx, other_id);
        return 1;
    }
    if (strcmp(type, "unfriend") == 0) {
        int other_id = 0;
        if (!jget_int(buf, "other_id", &other_id) || other_id <= 0) {
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid other_id\"}");
            return 1;
        }
        handle_friend_remove(idx, other_id);
        return 1;
    }
    if (strcmp(type, "search_user") == 0) {
        char query[128] = {0};
        jget(buf, "query", query, sizeof(query));
        handle_search_user(idx, query);
        return 1;
    }
    return 0;
}
