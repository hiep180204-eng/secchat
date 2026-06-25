/*
 * services/blocking.c — chặn/bỏ chặn người dùng (block/unblock + danh sách bị chặn).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blocking.h"
#include "clients.h"
#include "json_helpers.h"
#include "log.h"
#include "block_repo.h"

static void handle_block_user(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);
    int target_id = 0;
    jget_int(buf, "user_id", &target_id);

    if (target_id <= 0 || target_id == my_uid) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid user_id\"}");
        return;
    }
    if (!block_create(my_uid, target_id)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to block user\"}");
        return;
    }
    char resp[128];
    snprintf(resp, sizeof(resp),
             "{\"type\":\"ok\",\"msg\":\"User blocked\",\"user_id\":%d}",
             target_id);
    clients_send(idx, resp);
    log_info("blocking: uid=%d blocked uid=%d", my_uid, target_id);
}

static void handle_unblock_user(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);
    int target_id = 0;
    jget_int(buf, "user_id", &target_id);

    if (target_id <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid user_id\"}");
        return;
    }
    block_delete(my_uid, target_id);
    char resp[128];
    snprintf(resp, sizeof(resp),
             "{\"type\":\"ok\",\"msg\":\"User unblocked\",\"user_id\":%d}",
             target_id);
    clients_send(idx, resp);
    log_info("blocking: uid=%d unblocked uid=%d", my_uid, target_id);
}

static void handle_get_blocked_list(int idx)
{
    int my_uid = clients_get_uid(idx);
    int ids[200];
    int n = block_list_for_user(my_uid, ids, 200);

    char *out = (char *)malloc((size_t)n * 16 + 64);
    if (!out) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    int pos = snprintf(out, 64, "{\"type\":\"blocked_list\",\"users\":[");
    for (int i = 0; i < n; i++) {
        if (i > 0) out[pos++] = ',';
        pos += snprintf(out + pos, 20, "%d", ids[i]);
    }
    snprintf(out + pos, 4, "]}");
    clients_send(idx, out);
    free(out);
}

int blocking_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "block_user") == 0) {
        handle_block_user(idx, buf);
        return 1;
    }
    if (strcmp(type, "unblock_user") == 0) {
        handle_unblock_user(idx, buf);
        return 1;
    }
    if (strcmp(type, "get_blocked_list") == 0) {
        handle_get_blocked_list(idx);
        return 1;
    }
    return 0;
}
