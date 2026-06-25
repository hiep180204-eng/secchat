/*
 * repository/block_repo.c — truy cập bảng `user_blocks` (quan hệ chặn người dùng).
 *
 * Chặn là một chiều (blocker -> blocked). Các service dùng `block_either` để kiểm
 * hai chiều khi quyết định cho phép gửi/mở DM.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql/mysql.h>

#include "block_repo.h"
#include "db_pool.h"
#include "log.h"

/* Tạo quan hệ chặn (blocker chặn blocked); INSERT IGNORE nên gọi lại không lỗi. */
int block_create(int blocker_id, int blocked_id)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "INSERT IGNORE INTO user_blocks(blocker_id, blocked_id)"
             " VALUES(%d,%d)",
             blocker_id, blocked_id);
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);
    return ok;
}

/* Gỡ quan hệ chặn (bỏ chặn). */
int block_delete(int blocker_id, int blocked_id)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "DELETE FROM user_blocks"
             " WHERE blocker_id=%d AND blocked_id=%d",
             blocker_id, blocked_id);
    int ok = (mysql_query(conn, q) == 0);
    db_pool_release(conn);
    return ok;
}

/* True nếu blocker đang chặn blocked (kiểm MỘT chiều). */
int block_exists(int blocker_id, int blocked_id)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT 1 FROM user_blocks"
             " WHERE blocker_id=%d AND blocked_id=%d LIMIT 1",
             blocker_id, blocked_id);
    int found = 0;
    if (mysql_query(conn, q) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res) {
            found = (mysql_num_rows(res) > 0);
            mysql_free_result(res);
        }
    }
    db_pool_release(conn);
    return found;
}

/* True nếu một trong hai chiều có chặn (dùng để chặn gửi/mở DM hai phía). */
int block_either(int uid1, int uid2)
{
    return block_exists(uid1, uid2) || block_exists(uid2, uid1);
}

/* Điền out_ids các user mà uid đã chặn (tối đa max). Trả về số lượng. */
int block_list_for_user(int uid, int *out_ids, int max)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT blocked_id FROM user_blocks"
             " WHERE blocker_id=%d LIMIT %d",
             uid, max);
    int n = 0;
    if (mysql_query(conn, q) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res) {
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)) && n < max)
                out_ids[n++] = atoi(row[0]);
            mysql_free_result(res);
        }
    }
    db_pool_release(conn);
    return n;
}
