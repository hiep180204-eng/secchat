/*
 * services/pin_service.c — handler ghim tin nhắn.
 *
 * Xử lý: pin_message, unpin_message, get_pinned_messages.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql/mysql.h>

#include "pin_service.h"
#include "clients.h"
#include "json_helpers.h"
#include "db_pool.h"
#include "conversation_repo.h"
#include "message_repo.h"

#define MAX_PINNED_WIRE_PREVIEW 2048
#define PINNED_JSON_CAP (256 * 1024)

static void handle_pin_message(int idx, const char *buf)
{
    int my_uid   = clients_get_uid(idx);
    int msg_id_i = 0;
    jget_int(buf, "message_id", &msg_id_i);
    if (msg_id_i <= 0) return;
    long long msg_id = (long long)msg_id_i;

    long long cid = msg_get_conv_id(msg_id);
    if (cid < 0) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Message not found\"}"); return; }
    if (!conv_is_member(cid, my_uid)) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}"); return; }

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    char q[256];
    snprintf(q, sizeof(q),
             "INSERT IGNORE INTO pinned_messages(conversation_id, message_id, pinned_by)"
             " VALUES(%lld, %lld, %d)", cid, msg_id, my_uid);
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);
    if (!ok) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to pin message\"}"); return; }

    char notif[128];
    snprintf(notif, sizeof(notif),
             "{\"type\":\"message_pinned\",\"conversation_id\":%lld,"
             "\"message_id\":%lld,\"pinned_by\":%d}",
             cid, msg_id, my_uid);
    clients_broadcast_conv(cid, notif);
}

static void handle_unpin_message(int idx, const char *buf)
{
    int my_uid   = clients_get_uid(idx);
    int msg_id_i = 0;
    jget_int(buf, "message_id", &msg_id_i);
    if (msg_id_i <= 0) return;
    long long msg_id = (long long)msg_id_i;

    long long cid = msg_get_conv_id(msg_id);
    if (cid < 0) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Message not found\"}"); return; }
    if (!conv_is_member(cid, my_uid)) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}"); return; }

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    char q[256];
    snprintf(q, sizeof(q),
             "DELETE FROM pinned_messages"
             " WHERE conversation_id=%lld AND message_id=%lld",
             cid, msg_id);
    mysql_query(conn, q);
    db_pool_release(conn);

    char notif[128];
    snprintf(notif, sizeof(notif),
             "{\"type\":\"message_unpinned\",\"conversation_id\":%lld,"
             "\"message_id\":%lld}", cid, msg_id);
    clients_broadcast_conv(cid, notif);
}

static void handle_get_pinned_messages(int idx, const char *buf)
{
    int my_uid    = clients_get_uid(idx);
    int conv_id_i = 0;
    jget_int(buf, "conversation_id", &conv_id_i);
    if (conv_id_i <= 0) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid conversation_id\"}"); return; }
    long long cid = (long long)conv_id_i;
    if (!conv_is_member(cid, my_uid)) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}"); return; }

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    char q[512];
    snprintf(q, sizeof(q),
             "SELECT pm.message_id, m.sender_id, u.username, LEFT(m.body,%d),"
             " m.sent_at, pm.pinned_by, pm.pinned_at"
             " FROM pinned_messages pm"
             " JOIN messages m ON pm.message_id=m.id"
             " JOIN users u ON m.sender_id=u.id"
             " WHERE pm.conversation_id=%lld AND m.deleted_at IS NULL"
             " ORDER BY pm.pinned_at ASC LIMIT 50",
             MAX_PINNED_WIRE_PREVIEW, cid);
    if (mysql_query(conn, q)) { db_pool_release(conn); return; }
    MYSQL_RES *res = mysql_store_result(conn);
    db_pool_release(conn);
    if (!res) return;

    char *out = (char *)malloc(PINNED_JSON_CAP);
    if (!out) { mysql_free_result(res); return; }
    size_t pos = (size_t)snprintf(out, PINNED_JSON_CAP,
        "{\"type\":\"pinned_messages\",\"conversation_id\":%lld,\"messages\":[", cid);
    MYSQL_ROW row;
    int first = 1;
    while ((row = mysql_fetch_row(res))) {
        char eb[MAX_PINNED_WIRE_PREVIEW * 2 + 16]; char eu[130];
        json_esc(row[3] ? row[3] : "", eb, sizeof(eb));
        json_esc(row[2] ? row[2] : "", eu, sizeof(eu));
        if (pos + (MAX_PINNED_WIRE_PREVIEW * 2 + 1024) >= PINNED_JSON_CAP)
            break;
        if (!first) out[pos++] = ',';
        first = 0;
        pos += (size_t)snprintf(out + pos, PINNED_JSON_CAP - pos,
            "{\"message_id\":%s,\"sender_id\":%s,\"sender\":\"%s\","
            "\"body\":\"%s\",\"sent_at\":\"%s\","
            "\"pinned_by\":%s,\"pinned_at\":\"%s\"}",
            row[0], row[1], eu, eb, row[4] ? row[4] : "",
            row[5], row[6] ? row[6] : "");
    }
    snprintf(out + pos, PINNED_JSON_CAP - pos, "]}");
    mysql_free_result(res);
    clients_send(idx, out);
    free(out);
}

int pin_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "pin_message") == 0) {
        handle_pin_message(idx, buf);
        return 1;
    }
    if (strcmp(type, "unpin_message") == 0) {
        handle_unpin_message(idx, buf);
        return 1;
    }
    if (strcmp(type, "get_pinned_messages") == 0) {
        handle_get_pinned_messages(idx, buf);
        return 1;
    }
    return 0;
}
