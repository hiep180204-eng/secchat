/*
 * repository/notification_repo.c — hàng đợi thông báo cho người dùng OFFLINE.
 *
 * Khi người nhận không online, sự kiện (tin mới, lời mời kết bạn...) được xếp vào
 * bảng `notification_queue`; lúc họ đăng nhập lại, server flush các thông báo
 * chưa gửi rồi đánh dấu is_sent.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql/mysql.h>

#include "notification_repo.h"
#include "db_pool.h"
#include "log.h"

/* Xếp một thông báo (type + payload JSON) vào hàng đợi cho user. Trả 1 nếu ok. */
int notif_enqueue(int user_id, const char *type, const char *payload)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;

    const char *sql =
        "INSERT INTO notification_queue(user_id, type, payload, is_sent)"
        " VALUES(?, ?, ?, 0)";
    MYSQL_STMT *s = mysql_stmt_init(conn);
    if (!s) { db_pool_release(conn); return 0; }
    if (mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql))) {
        mysql_stmt_close(s); db_pool_release(conn); return 0;
    }

    MYSQL_BIND b[3];
    memset(b, 0, sizeof(b));
    unsigned long type_ul    = (unsigned long)strlen(type);
    unsigned long payload_ul = (unsigned long)strlen(payload);

    b[0].buffer_type = MYSQL_TYPE_LONG;
    b[0].buffer      = &user_id;

    b[1].buffer_type   = MYSQL_TYPE_STRING;
    b[1].buffer        = (void *)type;
    b[1].buffer_length = type_ul;
    b[1].length        = &type_ul;

    b[2].buffer_type   = MYSQL_TYPE_STRING;
    b[2].buffer        = (void *)payload;
    b[2].buffer_length = payload_ul;
    b[2].length        = &payload_ul;

    mysql_stmt_bind_param(s, b);
    int ok = (mysql_stmt_execute(s) == 0);
    mysql_stmt_close(s);
    db_pool_release(conn);
    return ok;
}

/* Lấy tối đa max thông báo CHƯA gửi của user (theo thứ tự id). Trả về số lượng. */
int notif_flush_for_user(int user_id, NotifRecord *out, int max)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT id, type, payload FROM notification_queue"
             " WHERE user_id=%d AND is_sent=0"
             " ORDER BY id ASC LIMIT %d",
             user_id, max);
    int n = 0;
    if (mysql_query(conn, q) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res) {
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) && n < max) {
                out[n].id = atoll(row[0]);
                strncpy(out[n].type,    row[1] ? row[1] : "", 63);
                out[n].type[63] = '\0';
                strncpy(out[n].payload, row[2] ? row[2] : "", 4095);
                out[n].payload[4095] = '\0';
                n++;
            }
            mysql_free_result(res);
        }
    }
    db_pool_release(conn);
    return n;
}

/* Đánh dấu một thông báo đã được gửi (is_sent=1) để không gửi lại. */
int notif_mark_sent(long long notif_id)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    char q[128];
    snprintf(q, sizeof(q),
             "UPDATE notification_queue SET is_sent=1 WHERE id=%lld",
             notif_id);
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);
    return ok;
}
