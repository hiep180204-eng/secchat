/*
 * repository/conversation_repo.c — truy cập bảng hội thoại và thành viên
 * (conversations, conversation_members, group_roles): tạo DM/group, thêm/bớt
 * thành viên, vai trò, ẩn/disband.
 */
#include "conversation_repo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql/mysql.h>

#include "db_pool.h"
#include "log.h"
#include "metrics.h"
#include "json_helpers.h"

/* ── Write operations ─────────────────────────────────────────────────────── */

long long conv_find_or_create_dm(int user1_id, int user2_id)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return -1;

    /* Look for existing DM */
    char q[512];
    snprintf(q, sizeof(q),
             "SELECT c.id FROM conversations c"
             " JOIN conversation_members cm1 ON c.id=cm1.conversation_id"
             " JOIN conversation_members cm2 ON c.id=cm2.conversation_id"
             " WHERE c.type='direct'"
             "   AND cm1.user_id=%d AND cm2.user_id=%d LIMIT 1",
             user1_id, user2_id);

    long long conv_id = -1;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) conv_id = atoll(row[0]);
            mysql_free_result(res);
        }
    }
    if (conv_id > 0) { db_pool_release(c); return conv_id; }

    /* Create new DM conversation */
    if (mysql_query(c, "INSERT INTO conversations(type) VALUES('direct')")) {
        db_pool_release(c); return -1;
    }
    conv_id = (long long)mysql_insert_id(c);

    if (user1_id == user2_id) {
        snprintf(q, sizeof(q),
                 "INSERT INTO conversation_members(conversation_id,user_id)"
                 " VALUES(%lld,%d)",
                 conv_id, user1_id);
    } else {
        snprintf(q, sizeof(q),
                 "INSERT INTO conversation_members(conversation_id,user_id)"
                 " VALUES(%lld,%d),(%lld,%d)",
                 conv_id, user1_id, conv_id, user2_id);
    }
    if (mysql_query(c, q))
        log_error("conv_create_dm: member insert: %s", mysql_error(c));

    db_pool_release(c);
    return conv_id;
}

long long conv_create_group(const char *name, int creator_id)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return -1;

    /* Use prepared statement for the group name to prevent injection */
    const char *sql =
        "INSERT INTO conversations(type, name, creator_id) VALUES('group', ?, ?)";

    MYSQL_STMT *s = mysql_stmt_init(c);
    if (!s) { db_pool_release(c); return -1; }
    if (mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql))) {
        mysql_stmt_close(s); db_pool_release(c); return -1;
    }

    MYSQL_BIND b[2];
    memset(b, 0, sizeof(b));
    unsigned long nlen = (unsigned long)strlen(name);
    b[0].buffer_type   = MYSQL_TYPE_STRING;
    b[0].buffer        = (void *)name;
    b[0].buffer_length = nlen;
    b[1].buffer_type   = MYSQL_TYPE_LONG;
    b[1].buffer        = &creator_id;

    if (mysql_stmt_bind_param(s, b) || mysql_stmt_execute(s)) {
        log_warn("conv_create_group stmt: %s", mysql_stmt_error(s));
        mysql_stmt_close(s); db_pool_release(c); return -1;
    }
    long long conv_id = (long long)mysql_stmt_insert_id(s);
    mysql_stmt_close(s);
    db_pool_release(c);
    return conv_id;
}

int conv_add_member(long long conv_id, int user_id)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "INSERT IGNORE INTO conversation_members(conversation_id,user_id)"
             " VALUES(%lld,%d)",
             conv_id, user_id);
    int rc = (mysql_query(c, q) == 0) ? 1 : 0;
    db_pool_release(c);
    return rc;
}

int conv_reset_hidden(long long conv_id)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "UPDATE conversation_members SET hidden_at=NULL"
             " WHERE conversation_id=%lld", conv_id);
    int rc = (mysql_query(c, q) == 0) ? 1 : 0;
    db_pool_release(c);
    return rc;
}

int conv_touch(long long conv_id)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[128];
    snprintf(q, sizeof(q),
             "UPDATE conversations SET last_message_at=NOW() WHERE id=%lld", conv_id);
    int rc = (mysql_query(c, q) == 0) ? 1 : 0;
    db_pool_release(c);
    return rc;
}

/* ── Read operations ──────────────────────────────────────────────────────── */

int conv_is_member(long long conv_id, int uid)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT 1 FROM conversation_members"
             " WHERE conversation_id=%lld AND user_id=%d LIMIT 1",
             conv_id, uid);
    int found = 0;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) { found = (mysql_fetch_row(res) != NULL); mysql_free_result(res); }
    }
    db_pool_release(c);
    return found;
}

int conv_is_disbanded(long long conv_id)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[128];
    snprintf(q, sizeof(q),
             "SELECT is_disbanded FROM conversations WHERE id=%lld LIMIT 1", conv_id);
    int disbanded = 0;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0]) disbanded = atoi(row[0]);
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    return disbanded;
}

int conv_get_members(long long conv_id, int *uids, int max)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT user_id FROM conversation_members"
             " WHERE conversation_id=%lld LIMIT %d",
             conv_id, max);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return 0;
    int count = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res)) && count < max)
        uids[count++] = atoi(row[0]);
    mysql_free_result(res);
    return count;
}

int conv_remove_member(long long conv_id, int uid)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "DELETE FROM conversation_members"
             " WHERE conversation_id=%lld AND user_id=%d",
             conv_id, uid);
    int rc = (mysql_query(c, q) == 0) ? 1 : 0;
    db_pool_release(c);
    return rc;
}

/* ── Group roles ──────────────────────────────────────────────────────────── */

int conv_role_set(long long conv_id, int uid, const char *role)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    static const char *sql =
        "INSERT INTO group_roles(conversation_id, user_id, role)"
        " VALUES(?, ?, ?)"
        " ON DUPLICATE KEY UPDATE role=VALUES(role)";
    unsigned long rlen = (unsigned long)strlen(role);
    MYSQL_BIND b[3]; memset(b, 0, sizeof(b));
    b[0].buffer_type   = MYSQL_TYPE_LONGLONG;
    b[0].buffer        = (void *)&conv_id;
    b[1].buffer_type   = MYSQL_TYPE_LONG;
    b[1].buffer        = (void *)&uid;
    b[2].buffer_type   = MYSQL_TYPE_STRING;
    b[2].buffer        = (void *)role;
    b[2].buffer_length = rlen;

    MYSQL_STMT *s = mysql_stmt_init(c);
    int rc = 0;
    if (s) {
        if (!mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql)) &&
            !mysql_stmt_bind_param(s, b)) {
            uint64_t t0 = metrics_now_us();
            rc = (mysql_stmt_execute(s) == 0) ? 1 : 0;
            metrics_lat_db_us(metrics_now_us() - t0);
            metrics_db_query(rc);
        }
        mysql_stmt_close(s);
    }
    db_pool_release(c);
    return rc;
}

int conv_role_delete(long long conv_id, int uid)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[192];
    snprintf(q, sizeof(q),
             "DELETE FROM group_roles WHERE conversation_id=%lld AND user_id=%d",
             conv_id, uid);
    int rc = (mysql_query(c, q) == 0) ? 1 : 0;
    db_pool_release(c);
    return rc;
}

int conv_is_admin(long long conv_id, int uid)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT 1 FROM group_roles"
             " WHERE conversation_id=%lld AND user_id=%d AND role='admin' LIMIT 1",
             conv_id, uid);
    int found = 0;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) { found = (mysql_fetch_row(res) != NULL); mysql_free_result(res); }
    }
    db_pool_release(c);
    return found;
}

void conv_get_member_ids_json(long long conv_id, char *out, size_t out_sz)
{
    out[0] = '['; out[1] = '\0';
    MYSQL *c = db_pool_acquire();
    if (!c) { strncat(out, "]", out_sz - strlen(out) - 1); return; }

    char q[256];
    snprintf(q, sizeof(q),
             "SELECT user_id FROM conversation_members"
             " WHERE conversation_id=%lld LIMIT 500",
             conv_id);
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row;
            int first = 1;
            while ((row = mysql_fetch_row(res))) {
                if (!first) strncat(out, ",", out_sz - strlen(out) - 1);
                strncat(out, row[0], out_sz - strlen(out) - 1);
                first = 0;
            }
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    strncat(out, "]", out_sz - strlen(out) - 1);
}

void conv_get_members_roles_json(long long conv_id, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;
    out[0] = '[';
    if (out_sz > 1) out[1] = '\0';

    MYSQL *c = db_pool_acquire();
    if (!c) {
        strncat(out, "]", out_sz - strlen(out) - 1);
        return;
    }

    char q[512];
    snprintf(q, sizeof(q),
             "SELECT cm.user_id, COALESCE(gr.role,'member')"
             " FROM conversation_members cm"
             " LEFT JOIN group_roles gr"
             "   ON gr.conversation_id=cm.conversation_id AND gr.user_id=cm.user_id"
             " WHERE cm.conversation_id=%lld"
             " ORDER BY cm.user_id ASC LIMIT 500",
             conv_id);
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row;
            int first = 1;
            while ((row = mysql_fetch_row(res))) {
                if (!first) strncat(out, ",", out_sz - strlen(out) - 1);
                first = 0;
                char item[96];
                snprintf(item, sizeof(item),
                         "{\"user_id\":%s,\"role\":\"%s\"}",
                         row[0] ? row[0] : "0",
                         row[1] ? row[1] : "member");
                strncat(out, item, out_sz - strlen(out) - 1);
            }
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    strncat(out, "]", out_sz - strlen(out) - 1);
}

int conv_update_info(long long conv_id,
                     const char *name,
                     const char *description,
                     const unsigned char *avatar_data, size_t avatar_len,
                     const char *avatar_mime)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    int ok = 1;
    if (name && name[0]) {
        const char *sql = "UPDATE conversations SET name=? WHERE id=?";
        MYSQL_STMT *s = mysql_stmt_init(c);
        if (s && mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql)) == 0) {
            MYSQL_BIND b[2]; memset(b, 0, sizeof(b));
            unsigned long nlen = (unsigned long)strlen(name);
            b[0].buffer_type   = MYSQL_TYPE_STRING;
            b[0].buffer        = (void *)name;
            b[0].buffer_length = nlen;
            b[1].buffer_type   = MYSQL_TYPE_LONGLONG;
            b[1].buffer        = &conv_id;
            mysql_stmt_bind_param(s, b);
            if (mysql_stmt_execute(s)) ok = 0;
        } else ok = 0;
        if (s) mysql_stmt_close(s);
    }
    if (description && description[0] && ok) {
        const char *sql = "UPDATE conversations SET description=? WHERE id=?";
        MYSQL_STMT *s = mysql_stmt_init(c);
        if (s && mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql)) == 0) {
            MYSQL_BIND b[2]; memset(b, 0, sizeof(b));
            unsigned long dlen = (unsigned long)strlen(description);
            b[0].buffer_type   = MYSQL_TYPE_STRING;
            b[0].buffer        = (void *)description;
            b[0].buffer_length = dlen;
            b[1].buffer_type   = MYSQL_TYPE_LONGLONG;
            b[1].buffer        = &conv_id;
            mysql_stmt_bind_param(s, b);
            if (mysql_stmt_execute(s)) ok = 0;
        } else ok = 0;
        if (s) mysql_stmt_close(s);
    }
    if (avatar_data && avatar_len > 0 && avatar_mime && ok) {
        const char *sql =
            "UPDATE conversations SET avatar=?, avatar_mime=? WHERE id=?";
        MYSQL_STMT *s = mysql_stmt_init(c);
        if (s && mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql)) == 0) {
            MYSQL_BIND b[3]; memset(b, 0, sizeof(b));
            unsigned long alen = (unsigned long)avatar_len;
            unsigned long mlen = (unsigned long)strlen(avatar_mime);
            b[0].buffer_type   = MYSQL_TYPE_BLOB;
            b[0].buffer        = (void *)avatar_data;
            b[0].buffer_length = alen;
            b[0].length        = &alen;
            b[1].buffer_type   = MYSQL_TYPE_STRING;
            b[1].buffer        = (void *)avatar_mime;
            b[1].buffer_length = mlen;
            b[2].buffer_type   = MYSQL_TYPE_LONGLONG;
            b[2].buffer        = &conv_id;
            mysql_stmt_bind_param(s, b);
            if (mysql_stmt_execute(s)) ok = 0;
        } else ok = 0;
        if (s) mysql_stmt_close(s);
    }
    db_pool_release(c);
    return ok;
}

int conv_get_group_info_json(long long conv_id, char *out, size_t out_sz)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    /* Fetch group metadata */
    char q[512];
    snprintf(q, sizeof(q),
             "SELECT name, description, creator_id, is_disbanded"
             " FROM conversations WHERE id=%lld AND type='group' LIMIT 1",
             conv_id);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    if (!res) { db_pool_release(c); return 0; }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); db_pool_release(c); return 0; }

    char esc_name[210], esc_desc[4100];
    json_esc(row[0] ? row[0] : "", esc_name, sizeof(esc_name));
    json_esc(row[1] ? row[1] : "", esc_desc, sizeof(esc_desc));
    int creator_id   = row[2] ? atoi(row[2]) : 0;
    int is_disbanded = row[3] ? atoi(row[3]) : 0;
    mysql_free_result(res);

    /* Fetch members with roles */
    snprintf(q, sizeof(q),
             "SELECT cm.user_id, u.username, COALESCE(gr.role,'member')"
             " FROM conversation_members cm"
             " JOIN users u ON cm.user_id=u.id"
             " LEFT JOIN group_roles gr"
             "   ON gr.conversation_id=cm.conversation_id AND gr.user_id=cm.user_id"
             " WHERE cm.conversation_id=%lld"
             " ORDER BY cm.joined_at ASC",
             conv_id);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *mres = mysql_store_result(c);
    db_pool_release(c);
    if (!mres) return 0;

    int pos = snprintf(out, out_sz,
             "{\"type\":\"group_info\",\"group_id\":%lld,"
             "\"name\":\"%s\",\"description\":\"%s\","
             "\"creator_id\":%d,\"is_disbanded\":%s,\"members\":[",
             conv_id, esc_name, esc_desc, creator_id,
             is_disbanded ? "true" : "false");

    MYSQL_ROW mr;
    int first = 1;
    while ((mr = mysql_fetch_row(mres))) {
        char eu[130];
        json_esc(mr[1] ? mr[1] : "", eu, sizeof(eu));
        if (!first) pos += snprintf(out + pos, out_sz - pos, ",");
        first = 0;
        pos += snprintf(out + pos, out_sz - pos,
                        "{\"user_id\":%s,\"username\":\"%s\",\"role\":\"%s\"}",
                        mr[0], eu, mr[2] ? mr[2] : "member");
    }
    snprintf(out + pos, out_sz - pos, "]}");
    mysql_free_result(mres);
    return 1;
}

int conv_get_dm_partners(int uid, int *uids, int max)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[512];
    snprintf(q, sizeof(q),
             "SELECT cm2.user_id"
             " FROM conversations cv"
             " JOIN conversation_members cm1"
             "   ON cv.id=cm1.conversation_id AND cm1.user_id=%d"
             " JOIN conversation_members cm2"
             "   ON cv.id=cm2.conversation_id AND cm2.user_id!=%d"
             " WHERE cv.type='direct'",
             uid, uid);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return 0;

    int count = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res)) && count < max) {
        uids[count++] = atoi(row[0]);
    }
    mysql_free_result(res);
    return count;
}
