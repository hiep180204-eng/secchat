/*
 * services/reaction_service.c — handler thả cảm xúc (reaction) cho tin nhắn.
 *
 * Xử lý: add_reaction, remove_reaction.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql/mysql.h>

#include "reaction_service.h"
#include "clients.h"
#include "json_helpers.h"
#include "metrics.h"
#include "db_pool.h"
#include "conversation_repo.h"
#include "message_repo.h"
#include "validation.h"

static void handle_add_reaction(int idx, const char *buf)
{
    int my_uid   = clients_get_uid(idx);
    int msg_id_i = 0;
    char emoji[32] = {0};
    jget_int(buf, "message_id", &msg_id_i);
    jget(buf, "emoji", emoji, sizeof(emoji));
    if (msg_id_i <= 0 || !domain_validate_emoji(emoji)) {
        metrics_validation_error();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid message_id or emoji\"}");
        return;
    }

    long long msg_id = (long long)msg_id_i;
    long long cid    = msg_get_conv_id(msg_id);
    if (cid < 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Message not found\"}");
        return;
    }
    if (!conv_is_member(cid, my_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}");
        return;
    }

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;

    const char *ins_sql =
        "INSERT IGNORE INTO message_reactions(message_id, user_id, emoji)"
        " VALUES(?, ?, ?)";
    MYSQL_STMT *s = mysql_stmt_init(conn);
    if (!s) { db_pool_release(conn); return; }
    if (mysql_stmt_prepare(s, ins_sql, (unsigned long)strlen(ins_sql))) {
        mysql_stmt_close(s); db_pool_release(conn); return;
    }
    MYSQL_BIND rb[3];
    memset(rb, 0, sizeof(rb));
    unsigned long emoji_len = (unsigned long)strlen(emoji);
    rb[0].buffer_type = MYSQL_TYPE_LONGLONG; rb[0].buffer = &msg_id;
    rb[1].buffer_type = MYSQL_TYPE_LONG;     rb[1].buffer = &my_uid;
    rb[2].buffer_type   = MYSQL_TYPE_STRING;
    rb[2].buffer        = emoji;
    rb[2].buffer_length = emoji_len;
    mysql_stmt_bind_param(s, rb);
    int ok = (mysql_stmt_execute(s) == 0);
    my_ulonglong changed = ok ? mysql_stmt_affected_rows(s) : 0;
    mysql_stmt_close(s);
    db_pool_release(conn);

    if (!ok || changed == 0) return;

    metrics_reaction_added();
    char esc_emoji[64];
    json_esc(emoji, esc_emoji, sizeof(esc_emoji));
    char notif[256];
    snprintf(notif, sizeof(notif),
             "{\"type\":\"reaction_added\",\"message_id\":%lld,"
             "\"conversation_id\":%lld,\"user_id\":%d,\"emoji\":\"%s\"}",
             msg_id, cid, my_uid, esc_emoji);
    clients_broadcast_conv(cid, notif);
}

static void handle_remove_reaction(int idx, const char *buf)
{
    int my_uid   = clients_get_uid(idx);
    int msg_id_i = 0;
    char emoji[32] = {0};
    jget_int(buf, "message_id", &msg_id_i);
    jget(buf, "emoji", emoji, sizeof(emoji));
    if (msg_id_i <= 0 || !domain_validate_emoji(emoji)) {
        metrics_validation_error();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid message_id or emoji\"}");
        return;
    }

    long long msg_id = (long long)msg_id_i;
    long long cid    = msg_get_conv_id(msg_id);
    if (cid < 0) return;

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;

    char q[256];
    snprintf(q, sizeof(q),
             "DELETE FROM message_reactions"
             " WHERE message_id=%lld AND user_id=%d AND emoji='",
             msg_id, my_uid);
    char esc[128];
    unsigned long esc_len =
        mysql_real_escape_string(conn, esc, emoji, (unsigned long)strlen(emoji));
    size_t qlen = strlen(q);
    my_ulonglong changed = 0;
    if (qlen + esc_len + 2 < 512) {
        char full[512];
        snprintf(full, sizeof(full), "%s%s'", q, esc);
        if (mysql_query(conn, full) == 0)
            changed = mysql_affected_rows(conn);
    }
    db_pool_release(conn);
    if (changed == 0) return;

    char esc_emoji[64];
    json_esc(emoji, esc_emoji, sizeof(esc_emoji));
    char notif[256];
    snprintf(notif, sizeof(notif),
             "{\"type\":\"reaction_removed\",\"message_id\":%lld,"
             "\"conversation_id\":%lld,\"user_id\":%d,\"emoji\":\"%s\"}",
             msg_id, cid, my_uid, esc_emoji);
    clients_broadcast_conv(cid, notif);
}

int reaction_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "add_reaction") == 0) {
        handle_add_reaction(idx, buf);
        return 1;
    }
    if (strcmp(type, "remove_reaction") == 0) {
        handle_remove_reaction(idx, buf);
        return 1;
    }
    return 0;
}
