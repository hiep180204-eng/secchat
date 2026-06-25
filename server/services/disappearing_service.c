/*
 * services/disappearing_service.c — handler hẹn giờ tự hủy tin nhắn.
 *
 * Xử lý: set_disappearing.
 */

#include <stdio.h>
#include <string.h>

#include <mysql/mysql.h>

#include "disappearing_service.h"
#include "clients.h"
#include "json_helpers.h"
#include "db_pool.h"
#include "conversation_repo.h"

static void handle_set_disappearing(int idx, const char *buf)
{
    int my_uid    = clients_get_uid(idx);
    int conv_id_i = 0, secs = 0;
    jget_int(buf, "conversation_id",      &conv_id_i);
    jget_int(buf, "disappear_after_secs", &secs);
    if (conv_id_i <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid conversation_id\"}");
        return;
    }
    long long cid = (long long)conv_id_i;
    if (!conv_is_member(cid, my_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}"); return;
    }

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    char q[256];
    if (secs > 0)
        snprintf(q, sizeof(q),
                 "UPDATE conversations"
                 " SET disappear_after_secs=%d, disappear_enabled_at=NOW(3)"
                 " WHERE id=%lld",
                 secs, cid);
    else
        snprintf(q, sizeof(q),
                 "UPDATE conversations"
                 " SET disappear_after_secs=NULL, disappear_enabled_at=NULL"
                 " WHERE id=%lld",
                 cid);
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);

    if (!ok) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to set disappearing timer\"}"); return; }

    char notif[256];
    if (secs > 0)
        snprintf(notif, sizeof(notif),
                 "{\"type\":\"disappearing_updated\",\"conversation_id\":%lld,"
                 "\"disappear_after_secs\":%d,\"set_by\":%d}",
                 cid, secs, my_uid);
    else
        snprintf(notif, sizeof(notif),
                 "{\"type\":\"disappearing_updated\",\"conversation_id\":%lld,"
                 "\"disappear_after_secs\":null,\"set_by\":%d}",
                 cid, my_uid);
    clients_broadcast_conv(cid, notif);
}

int disappearing_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "set_disappearing") == 0) {
        handle_set_disappearing(idx, buf);
        return 1;
    }
    return 0;
}
