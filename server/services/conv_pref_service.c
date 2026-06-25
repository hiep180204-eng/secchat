/*
 * services/conv_pref_service.c — handler tùy chọn hội thoại theo từng người.
 *
 * Xử lý: mute_conversation, archive_conversation,
 *        pin_conversation, mark_unread, mark_read.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql/mysql.h>

#include "conv_pref_service.h"
#include "clients.h"
#include "json_helpers.h"
#include "db_pool.h"
#include "conversation_repo.h"

static void handle_mute_conversation(int idx, const char *buf)
{
    int my_uid    = clients_get_uid(idx);
    int conv_id_i = 0, secs = 0;
    jget_int(buf, "conversation_id", &conv_id_i);
    jget_int(buf, "mute_secs",       &secs);
    if (conv_id_i <= 0) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid conversation_id\"}"); return; }
    long long cid = (long long)conv_id_i;
    if (!conv_is_member(cid, my_uid)) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}"); return; }

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    char q[256];
    if (secs > 0)
        snprintf(q, sizeof(q),
                 "UPDATE conversation_members"
                 " SET muted_until=DATE_ADD(NOW(), INTERVAL %d SECOND)"
                 " WHERE conversation_id=%lld AND user_id=%d",
                 secs, cid, my_uid);
    else
        snprintf(q, sizeof(q),
                 "UPDATE conversation_members"
                 " SET muted_until=NULL"
                 " WHERE conversation_id=%lld AND user_id=%d",
                 cid, my_uid);
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);

    clients_send(idx, ok
        ? "{\"type\":\"ok\",\"msg\":\"Mute updated\"}"
        : "{\"type\":\"error\",\"msg\":\"Failed to update mute\"}");
}

static void handle_archive_conversation(int idx, const char *buf)
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
             "UPDATE conversation_members"
             " SET archived_at = CASE WHEN archived_at IS NULL THEN NOW() ELSE NULL END"
             " WHERE conversation_id=%lld AND user_id=%d",
             cid, my_uid);
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);
    clients_send(idx, ok
        ? "{\"type\":\"ok\",\"msg\":\"Archive status toggled\"}"
        : "{\"type\":\"error\",\"msg\":\"Failed to toggle archive\"}");
}

static void handle_pin_conversation(int idx, const char *buf)
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
             "UPDATE conversation_members"
             " SET conv_pinned_at = CASE WHEN conv_pinned_at IS NULL THEN NOW() ELSE NULL END"
             " WHERE conversation_id=%lld AND user_id=%d",
             cid, my_uid);
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);
    clients_send(idx, ok
        ? "{\"type\":\"ok\",\"msg\":\"Pin status toggled\"}"
        : "{\"type\":\"error\",\"msg\":\"Failed to toggle pin\"}");
}

static void handle_mark_unread(int idx, const char *buf)
{
    int my_uid    = clients_get_uid(idx);
    int conv_id_i = 0;
    jget_int(buf, "conversation_id", &conv_id_i);
    if (conv_id_i <= 0) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid conversation_id\"}"); return; }
    long long cid = (long long)conv_id_i;
    if (!conv_is_member(cid, my_uid)) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}"); return; }

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    char q[256];
    snprintf(q, sizeof(q),
             "UPDATE conversation_members SET force_unread=1"
             " WHERE conversation_id=%lld AND user_id=%d",
             cid, my_uid);
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);
    clients_send(idx, ok
        ? "{\"type\":\"ok\",\"msg\":\"Marked as unread\"}"
        : "{\"type\":\"error\",\"msg\":\"Failed to mark unread\"}");
}

static long long max_visible_message_id(MYSQL *conn, long long cid, int uid,
                                        long long upper_bound)
{
    char bound[128] = "";
    if (upper_bound > 0) {
        snprintf(bound, sizeof(bound), " AND m.id<=%lld", upper_bound);
    }

    char q[1024];
    snprintf(q, sizeof(q),
             "SELECT COALESCE(MAX(m.id),0)"
             " FROM messages m"
             " JOIN conversations c ON c.id=m.conversation_id"
             " JOIN conversation_members cm"
             "   ON cm.conversation_id=m.conversation_id AND cm.user_id=%d"
             " WHERE m.conversation_id=%lld"
             "   AND m.deleted_at IS NULL"
             "   AND (c.type!='group' OR m.sent_at >= cm.joined_at)"
             "   AND (m.body LIKE 'S3DR:%%'"
             "        OR m.body LIKE 'S3MLS:%%'"
             "        OR m.body LIKE 'FILE:%%')"
             "%s",
             uid, cid, bound);

    if (mysql_query(conn, q) != 0) return 0;
    MYSQL_RES *res = mysql_store_result(conn);
    if (!res) return 0;
    MYSQL_ROW row = mysql_fetch_row(res);
    long long value = (row && row[0]) ? atoll(row[0]) : 0;
    mysql_free_result(res);
    return value;
}

static void handle_mark_read(int idx, const char *buf)
{
    int my_uid    = clients_get_uid(idx);
    int conv_id_i = 0;
    int last_msg_i = 0;
    jget_int(buf, "conversation_id", &conv_id_i);
    if (conv_id_i <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid conversation_id\"}");
        return;
    }
    long long cid = (long long)conv_id_i;
    if (!conv_is_member(cid, my_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}");
        return;
    }

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    long long requested_id = 0;
    if (jget_int(buf, "last_message_id", &last_msg_i) && last_msg_i > 0) {
        requested_id = (long long)last_msg_i;
    }
    long long read_id = max_visible_message_id(conn, cid, my_uid, requested_id);

    char q[512];
    if (read_id > 0) {
        snprintf(q, sizeof(q),
                 "UPDATE conversation_members"
                 " SET last_read_at=NOW(3),"
                 "     last_read_message_id=GREATEST(COALESCE(last_read_message_id,0),%lld),"
                 "     force_unread=0"
                 " WHERE conversation_id=%lld AND user_id=%d",
                 read_id, cid, my_uid);
    } else {
        snprintf(q, sizeof(q),
                 "UPDATE conversation_members"
                 " SET last_read_at=NOW(3), force_unread=0"
                 " WHERE conversation_id=%lld AND user_id=%d",
                 cid, my_uid);
    }
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);
    clients_send(idx, ok
        ? "{\"type\":\"ok\",\"msg\":\"Marked as read\"}"
        : "{\"type\":\"error\",\"msg\":\"Failed to mark read\"}");
}

int conv_pref_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "mute_conversation") == 0) {
        handle_mute_conversation(idx, buf);
        return 1;
    }
    if (strcmp(type, "archive_conversation") == 0) {
        handle_archive_conversation(idx, buf);
        return 1;
    }
    if (strcmp(type, "pin_conversation") == 0) {
        handle_pin_conversation(idx, buf);
        return 1;
    }
    if (strcmp(type, "mark_unread") == 0) {
        handle_mark_unread(idx, buf);
        return 1;
    }
    if (strcmp(type, "mark_read") == 0) {
        handle_mark_read(idx, buf);
        return 1;
    }
    return 0;
}
