/*
 * services/presence.c — trạng thái online và quyền riêng tư hiển thị trạng thái.
 * Phát presence online/offline cho bạn bè và cấu hình ai được phép thấy.
 */
#include <stdio.h>
#include <string.h>

#include "clients.h"
#include "json_helpers.h"
#include "log.h"
#include "presence.h"
#include "user_repo.h"
#include "friendship_repo.h"
#include "block_repo.h"

/* ── Privacy helpers ─────────────────────────────────────────────────────── */

static void get_privacy(int uid, char *out_online, char *out_last_seen)
{
    strncpy(out_online,    "everyone", 15); out_online[15]    = '\0';
    strncpy(out_last_seen, "everyone", 15); out_last_seen[15] = '\0';

    user_repo_get_privacy(uid, out_online, 16, out_last_seen, 16);
}

static int can_see_status(int uid_viewer, int uid_subject, const char *privacy)
{
    if (strcmp(privacy, "everyone") == 0) return 1;
    if (strcmp(privacy, "nobody")   == 0) return 0;
    return friendship_exists_accepted(uid_viewer, uid_subject);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void presence_broadcast_online(int uid)
{
    if (uid <= 0) return;

    char privacy_online[16] = {0}, privacy_last_seen[16] = {0};
    get_privacy(uid, privacy_online, privacy_last_seen);

    if (strcmp(privacy_online, "nobody") == 0) return;

    UserRecord rec;
    if (!user_repo_find_by_id(uid, &rec)) return;

    FriendRecord friends[200];
    int n = friendship_list_for_user(uid, friends, 200);

    char notif[256];
    snprintf(notif, sizeof(notif),
             "{\"type\":\"presence\",\"user_id\":%d,\"username\":\"%s\","
             "\"status\":\"online\"}",
             uid, rec.username);

    for (int i = 0; i < n; i++) {
        if (block_either(uid, friends[i].id)) continue;
        if (strcmp(privacy_online, "friends") == 0 ||
            strcmp(privacy_online, "everyone") == 0) {
            clients_send_to_uid(friends[i].id, notif);
        }
    }
    log_info("presence: uid=%d online (privacy=%s)", uid, privacy_online);
}

void presence_broadcast_offline(int uid)
{
    if (uid <= 0) return;

    char privacy_online[16] = {0}, privacy_last_seen[16] = {0};
    get_privacy(uid, privacy_online, privacy_last_seen);

    user_repo_set_status(uid, "offline");

    if (strcmp(privacy_online, "nobody") == 0) return;

    UserRecord rec;
    if (!user_repo_find_by_id(uid, &rec)) return;

    FriendRecord friends[200];
    int n = friendship_list_for_user(uid, friends, 200);

    const char *last_seen = (strcmp(privacy_last_seen, "nobody") == 0)
        ? "" : rec.last_seen;
    char notif[256];
    snprintf(notif, sizeof(notif),
             "{\"type\":\"presence\",\"user_id\":%d,\"username\":\"%s\","
             "\"status\":\"offline\",\"last_seen\":\"%s\"}",
             uid, rec.username, last_seen);

    for (int i = 0; i < n; i++) {
        if (block_either(uid, friends[i].id)) continue;
        if (can_see_status(friends[i].id, uid, privacy_online))
            clients_send_to_uid(friends[i].id, notif);
    }
    log_info("presence: uid=%d offline", uid);
}

/* ── Privacy settings handlers ───────────────────────────────────────────── */

static void handle_update_privacy(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);

    char privacy_online[16]       = {0};
    char privacy_last_seen[16]    = {0};
    jget(buf, "privacy_online",       privacy_online,       sizeof(privacy_online));
    jget(buf, "privacy_last_seen",    privacy_last_seen,    sizeof(privacy_last_seen));

    const char *valid[] = {"everyone", "friends", "nobody", ""};
    int ok_online = 0, ok_ls = 0;
    for (int i = 0; valid[i][0] || i < 3; i++) {
        if (strcmp(privacy_online,       valid[i]) == 0) ok_online = 1;
        if (strcmp(privacy_last_seen,    valid[i]) == 0) ok_ls     = 1;
    }
    if (!ok_online && privacy_online[0]) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid privacy_online\"}");
        return;
    }
    if (!ok_ls && privacy_last_seen[0]) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid privacy_last_seen\"}");
        return;
    }
    if (strstr(buf, "\"privacy_read_receipt\"") != NULL) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Read receipts are not supported\"}");
        return;
    }

    if (!privacy_online[0] && !privacy_last_seen[0]) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"No privacy field provided\"}");
        return;
    }

    if (user_repo_update_privacy(my_uid, privacy_online, privacy_last_seen))
        clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Privacy settings updated\"}");
    else
        clients_send(idx,
            "{\"type\":\"error\",\"msg\":\"Failed to update privacy settings\"}");
}

static void handle_get_privacy(int idx)
{
    int my_uid = clients_get_uid(idx);
    char po[16] = "everyone", pls[16] = "everyone";
    user_repo_get_privacy(my_uid, po, sizeof(po), pls, sizeof(pls));

    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"type\":\"privacy_settings\","
             "\"privacy_online\":\"%s\","
             "\"privacy_last_seen\":\"%s\"}",
             po, pls);
    clients_send(idx, resp);
}

/* ── dispatcher ──────────────────────────────────────────────────────────── */

int presence_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "update_privacy") == 0) {
        handle_update_privacy(idx, buf);
        return 1;
    }
    if (strcmp(type, "get_privacy") == 0) {
        handle_get_privacy(idx);
        return 1;
    }
    return 0;
}
