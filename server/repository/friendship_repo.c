/*
 * repository/friendship_repo.c — truy cập bảng `friendships` (lời mời và quan hệ
 * bạn bè đã chấp nhận).
 */
#include "friendship_repo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql/mysql.h>

#include "db_pool.h"
#include "log.h"
#include "metrics.h"

/* ── Write operations ─────────────────────────────────────────────────────── */

int friendship_create_pending(int user_id, int friend_id, int requester_id)
{
    /* Canonical ordering: lower id in user_id column */
    int u1 = user_id < friend_id ? user_id : friend_id;
    int u2 = user_id < friend_id ? friend_id : user_id;

    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[512];
    snprintf(q, sizeof(q),
             "INSERT INTO friendships(user_id, friend_id, requester_id, status)"
             " VALUES(%d, %d, %d, 'pending')",
             u1, u2, requester_id);
    int rc = (mysql_query(c, q) == 0) ? 1 : 0;
    db_pool_release(c);
    return rc;
}

int friendship_accept(int my_uid, int requester_uid)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[512];
    snprintf(q, sizeof(q),
             "UPDATE friendships SET status='accepted', updated_at=NOW()"
             " WHERE ((user_id=%d AND friend_id=%d)"
             "     OR (user_id=%d AND friend_id=%d))"
             " AND requester_id=%d AND status='pending'",
             my_uid, requester_uid, requester_uid, my_uid, requester_uid);
    int rc = 0;
    if (mysql_query(c, q) == 0 && mysql_affected_rows(c) > 0)
        rc = 1;
    db_pool_release(c);
    return rc;
}

int friendship_delete(int uid_a, int uid_b)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[512];
    snprintf(q, sizeof(q),
             "DELETE FROM friendships"
             " WHERE (user_id=%d AND friend_id=%d)"
             "    OR (user_id=%d AND friend_id=%d)",
             uid_a, uid_b, uid_b, uid_a);
    mysql_query(c, q);   /* idempotent — ok if not found */
    db_pool_release(c);
    return 1;
}

/* ── Read operations ──────────────────────────────────────────────────────── */

int friendship_list_for_user(int uid, FriendRecord *out, int max)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[512];
    snprintf(q, sizeof(q),
             "SELECT u2.id, u2.username, u2.display_name,"
             " CASE WHEN u2.privacy_online='nobody' THEN 'offline' ELSE u2.status END,"
             " CASE WHEN u2.privacy_last_seen='nobody' THEN ''"
             "      ELSE DATE_FORMAT(u2.last_seen, '%%Y-%%m-%%d %%H:%%i:%%s') END"
             " FROM friendships f"
             " JOIN users u2"
             "   ON (f.user_id=%d AND f.friend_id=u2.id)"
             "   OR (f.friend_id=%d AND f.user_id=u2.id)"
             " WHERE f.status='accepted'",
             uid, uid);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return 0;

    int count = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res)) && count < max) {
        out[count].id = atoi(row[0]);
        strncpy(out[count].username,     row[1] ? row[1] : "", sizeof(out[count].username) - 1);
        strncpy(out[count].display_name, row[2] ? row[2] : "", sizeof(out[count].display_name) - 1);
        strncpy(out[count].status,       row[3] ? row[3] : "offline", sizeof(out[count].status) - 1);
        strncpy(out[count].last_seen,    row[4] ? row[4] : "", sizeof(out[count].last_seen) - 1);
        count++;
    }
    mysql_free_result(res);
    return count;
}

int friendship_list_pending(int uid, FriendRequestRecord *out, int max)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[512];
    snprintf(q, sizeof(q),
             "SELECT f.id, u.id, u.username, u.display_name, f.created_at"
             " FROM friendships f"
             " JOIN users u ON f.requester_id=u.id"
             " WHERE ((f.user_id=%d AND f.requester_id!=%d)"
             "     OR (f.friend_id=%d AND f.requester_id!=%d))"
             " AND f.status='pending'",
             uid, uid, uid, uid);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return 0;

    int count = 0;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res)) && count < max) {
        out[count].request_id = atoll(row[0]);
        out[count].user_id    = atoi(row[1]);
        strncpy(out[count].username,     row[2] ? row[2] : "", sizeof(out[count].username) - 1);
        strncpy(out[count].display_name, row[3] ? row[3] : "", sizeof(out[count].display_name) - 1);
        strncpy(out[count].requested_at, row[4] ? row[4] : "", sizeof(out[count].requested_at) - 1);
        count++;
    }
    mysql_free_result(res);
    return count;
}

int friendship_exists_accepted(int uid_a, int uid_b)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[512];
    snprintf(q, sizeof(q),
             "SELECT 1 FROM friendships"
             " WHERE ((user_id=%d AND friend_id=%d)"
             "     OR (user_id=%d AND friend_id=%d))"
             " AND status='accepted' LIMIT 1",
             uid_a, uid_b, uid_b, uid_a);
    int found = 0;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            found = (mysql_fetch_row(res) != NULL);
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    return found;
}

int friendship_get_status(int uid_a, int uid_b,
                          char *status, int status_len,
                          int *requester_id)
{
    int u1 = uid_a < uid_b ? uid_a : uid_b;
    int u2 = uid_a < uid_b ? uid_b : uid_a;

    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[256];
    snprintf(q, sizeof(q),
             "SELECT status, requester_id FROM friendships"
             " WHERE user_id=%d AND friend_id=%d LIMIT 1",
             u1, u2);
    int found = 0;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) {
                found = 1;
                if (status && status_len > 0) {
                    strncpy(status, row[0] ? row[0] : "", status_len - 1);
                    status[status_len - 1] = '\0';
                }
                if (requester_id)
                    *requester_id = row[1] ? atoi(row[1]) : 0;
            }
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    return found;
}
