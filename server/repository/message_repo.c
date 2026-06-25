/*
 * repository/message_repo.c — truy cập bảng `messages` bằng prepared statement.
 *
 * Chỉ lưu/đọc ciphertext (body có prefix S3*) và metadata; không giải mã. Các
 * thao tác ghi tự retry MỘT lần khi kết nối MySQL bị rớt giữa chừng.
 */
#include "message_repo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql/errmsg.h>
#include <mysql/mysql.h>

#include "db_pool.h"
#include "log.h"
#include "metrics.h"

#ifndef CR_SERVER_GONE_ERROR
#define CR_SERVER_GONE_ERROR 2006
#endif
#ifndef CR_SERVER_LOST
#define CR_SERVER_LOST 2013
#endif

/* True nếu lỗi statement là do mất kết nối MySQL (để quyết định có retry không). */
static int stmt_connection_lost(MYSQL_STMT *s)
{
    unsigned int err = s ? mysql_stmt_errno(s) : 0;
    return err == CR_SERVER_GONE_ERROR || err == CR_SERVER_LOST;
}

/* Chèn một message mới (ciphertext); trả về message_id > 0, hoặc -1 nếu lỗi. */
long long msg_insert(long long conv_id, int sender_id, const char *body)
{
    const char *sql =
        "INSERT INTO messages(conversation_id, sender_id, body) VALUES(?, ?, ?)";

    for (int attempt = 0; attempt < 2; attempt++) {
        MYSQL *c = db_pool_acquire();
        if (!c) return -1;

        MYSQL_STMT *s = mysql_stmt_init(c);
        if (!s) { db_pool_release(c); return -1; }
        if (mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql))) {
            int retry = (attempt == 0 && stmt_connection_lost(s));
            log_warn("msg_insert prepare%s: %s",
                     retry ? " (retrying)" : "", mysql_stmt_error(s));
            mysql_stmt_close(s);
            db_pool_release(c);
            if (retry) continue;
            return -1;
        }

        MYSQL_BIND b[3];
        memset(b, 0, sizeof(b));
        long long cid_ll  = conv_id;
        int       sid_i   = sender_id;
        unsigned long blen = (unsigned long)strlen(body);

        b[0].buffer_type   = MYSQL_TYPE_LONGLONG;
        b[0].buffer        = &cid_ll;
        b[1].buffer_type   = MYSQL_TYPE_LONG;
        b[1].buffer        = &sid_i;
        b[2].buffer_type   = MYSQL_TYPE_BLOB;
        b[2].buffer        = (void *)body;
        b[2].buffer_length = blen;
        b[2].length        = &blen;

        uint64_t t0 = metrics_now_us();
        if (mysql_stmt_bind_param(s, b) || mysql_stmt_execute(s)) {
            int retry = (attempt == 0 && stmt_connection_lost(s));
            metrics_lat_db_us(metrics_now_us() - t0);
            metrics_db_query(0);
            log_warn("msg_insert execute%s: %s",
                     retry ? " (retrying)" : "", mysql_stmt_error(s));
            mysql_stmt_close(s);
            db_pool_release(c);
            if (retry) continue;
            return -1;
        }
        metrics_lat_db_us(metrics_now_us() - t0);
        metrics_db_query(1);

        long long msg_id = (long long)mysql_stmt_insert_id(s);
        mysql_stmt_close(s);
        db_pool_release(c);
        return msg_id;
    }

    return -1;
}

/* Chèn một "edit event" trỏ về tin gốc qua edit_target_message_id
 * (event-sourced: KHÔNG ghi đè ciphertext gốc, để bản gốc không bị mất). */
long long msg_insert_edit_event(long long conv_id, int sender_id,
                                const char *body, long long target_msg_id)
{
    const char *sql =
        "INSERT INTO messages"
        "(conversation_id, sender_id, body, edit_target_message_id)"
        " VALUES(?, ?, ?, ?)";

    for (int attempt = 0; attempt < 2; attempt++) {
        MYSQL *c = db_pool_acquire();
        if (!c) return -1;

        MYSQL_STMT *s = mysql_stmt_init(c);
        if (!s) { db_pool_release(c); return -1; }
        if (mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql))) {
            int retry = (attempt == 0 && stmt_connection_lost(s));
            log_warn("msg_insert_edit_event prepare%s: %s",
                     retry ? " (retrying)" : "", mysql_stmt_error(s));
            mysql_stmt_close(s);
            db_pool_release(c);
            if (retry) continue;
            return -1;
        }

        MYSQL_BIND b[4];
        memset(b, 0, sizeof(b));
        long long cid_ll = conv_id;
        int sid_i = sender_id;
        long long target_ll = target_msg_id;
        unsigned long blen = (unsigned long)strlen(body);

        b[0].buffer_type = MYSQL_TYPE_LONGLONG;
        b[0].buffer = &cid_ll;
        b[1].buffer_type = MYSQL_TYPE_LONG;
        b[1].buffer = &sid_i;
        b[2].buffer_type = MYSQL_TYPE_BLOB;
        b[2].buffer = (void *)body;
        b[2].buffer_length = blen;
        b[2].length = &blen;
        b[3].buffer_type = MYSQL_TYPE_LONGLONG;
        b[3].buffer = &target_ll;

        uint64_t t0 = metrics_now_us();
        if (mysql_stmt_bind_param(s, b) || mysql_stmt_execute(s)) {
            int retry = (attempt == 0 && stmt_connection_lost(s));
            metrics_lat_db_us(metrics_now_us() - t0);
            metrics_db_query(0);
            log_warn("msg_insert_edit_event execute%s: %s",
                     retry ? " (retrying)" : "", mysql_stmt_error(s));
            mysql_stmt_close(s);
            db_pool_release(c);
            if (retry) continue;
            return -1;
        }
        metrics_lat_db_us(metrics_now_us() - t0);
        metrics_db_query(1);

        long long msg_id = (long long)mysql_stmt_insert_id(s);
        mysql_stmt_close(s);
        db_pool_release(c);
        return msg_id;
    }

    return -1;
}

/* Xóa mềm: đặt deleted_at=NOW(), body vẫn nằm trong DB. Chỉ người gửi xóa được.
 * Trả 1 nếu có dòng bị cập nhật, 0 nếu không. */
int msg_soft_delete(long long msg_id, int sender_id)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "UPDATE messages SET deleted_at=NOW(3)"
             " WHERE id=%lld AND sender_id=%d AND deleted_at IS NULL",
             msg_id, sender_id);
    int rc = 0;
    if (mysql_query(c, q) == 0 && mysql_affected_rows(c) > 0)
        rc = 1;
    db_pool_release(c);
    return rc;
}

/* Lấy conversation_id của một message (để broadcast sau edit/delete). -1 nếu không thấy. */
long long msg_get_conv_id(long long msg_id)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return -1;
    char q[128];
    snprintf(q, sizeof(q),
             "SELECT conversation_id FROM messages WHERE id=%lld LIMIT 1", msg_id);
    long long cid = -1;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) cid = atoll(row[0]);
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    return cid;
}

/* Lấy conv_id của một message CÒN sửa được của uid (chưa xóa, không phải edit-event). -1 nếu không. */
long long msg_get_editable_conv_id(long long msg_id, int uid)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return -1;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT conversation_id FROM messages"
             " WHERE id=%lld AND sender_id=%d"
             " AND deleted_at IS NULL AND edit_target_message_id IS NULL"
             " LIMIT 1",
             msg_id, uid);
    long long cid = -1;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) cid = atoll(row[0]);
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    return cid;
}
