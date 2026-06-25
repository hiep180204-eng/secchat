/*
 * services/messaging_service.c — các handler nhắn tin lõi của server.
 *
 * Server không giải mã nội dung tin nhắn. Nó chỉ kiểm tra membership, rate
 * limit, kích thước input, prefix wire-format E2EE S3, rồi lưu/forward
 * ciphertext. Các thao tác như inbox, history, pin/reaction/edit đều phải giữ
 * nguyên body mã hóa để client tự giải mã.
 *
 * Các command xử lý ở đây: message, history, get_inbox, start_dm,
 * edit_message, delete_message, typing_start, typing_stop.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mysql/mysql.h>

#include "messaging_service.h"
#include "clients.h"
#include "json_helpers.h"
#include "log.h"
#include "metrics.h"
#include "db_pool.h"
#include "conversation_repo.h"
#include "friendship_repo.h"
#include "message_repo.h"
#include "block_repo.h"
#include "ratelimit.h"
#include "validation.h"
#include "notification_repo.h"
#include "user_repo.h"

/* Giới hạn body ciphertext để tránh client gửi payload quá lớn làm server C
 * cấp phát bộ nhớ quá mức. Plaintext đã bị chặn ở validation prefix phía dưới. */
#define MAX_ENCRYPTED_MESSAGE_BODY (3 * 1024 * 1024)
#define MAX_INBOX_WIRE_PREVIEW 2048
#define INBOX_JSON_CAP (256 * 1024)

/* Lấy timestamp dạng "YYYY-MM-DD HH:MM:SS" bằng localtime_r để an toàn thread. */
static void now_ts(char *buf, size_t len)
{
    time_t t = time(NULL);
    struct tm tm_buf;
    struct tm *tm_p = localtime_r(&t, &tm_buf);
    if (tm_p) strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_p);
    else       snprintf(buf, len, "1970-01-01 00:00:00");
}

static int message_is_pinned(long long cid, long long msg_id)
{
    /* Pinned state không nằm trong bảng messages để có thể pin/unpin mà không
     * sửa ciphertext gốc. */
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT 1 FROM pinned_messages"
             " WHERE conversation_id=%lld AND message_id=%lld LIMIT 1",
             cid, msg_id);
    int pinned = 0;
    if (mysql_query(conn, q) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res) {
            pinned = (mysql_fetch_row(res) != NULL);
            mysql_free_result(res);
        }
    }
    db_pool_release(conn);
    return pinned;
}

static char *message_reactions_json(long long msg_id, int viewer_uid)
{
    /* Gom reaction thành JSON nhỏ để history có thể render lại chip emoji/count.
     * viewer_uid dùng để đánh dấu reaction nào là của chính user đang xem. */
    MYSQL *conn = db_pool_acquire();
    if (!conn) {
        char *empty = (char *)malloc(3);
        if (empty) strcpy(empty, "[]");
        return empty;
    }
    char q[512];
    snprintf(q, sizeof(q),
             "SELECT emoji, COUNT(*), SUM(user_id=%d), MIN(created_at) AS first_at"
             " FROM message_reactions WHERE message_id=%lld"
             " GROUP BY emoji ORDER BY first_at ASC LIMIT 32",
             viewer_uid, msg_id);
    if (mysql_query(conn, q)) {
        db_pool_release(conn);
        char *empty = (char *)malloc(3);
        if (empty) strcpy(empty, "[]");
        return empty;
    }
    MYSQL_RES *res = mysql_store_result(conn);
    db_pool_release(conn);
    if (!res) {
        char *empty = (char *)malloc(3);
        if (empty) strcpy(empty, "[]");
        return empty;
    }

    char *out = (char *)malloc(4096);
    if (!out) { mysql_free_result(res); return NULL; }
    size_t pos = (size_t)snprintf(out, 4096, "[");
    MYSQL_ROW row;
    int first = 1;
    while ((row = mysql_fetch_row(res))) {
        char ee[96];
        json_esc(row[0] ? row[0] : "", ee, sizeof(ee));
        if (!first) pos += (size_t)snprintf(out + pos, 4096 - pos, ",");
        first = 0;
        pos += (size_t)snprintf(out + pos, 4096 - pos,
            "{\"emoji\":\"%s\",\"count\":%s,\"me\":%s}",
            ee, row[1] ? row[1] : "0",
            (row[2] && atoi(row[2]) > 0) ? "true" : "false");
        if (pos >= 4000) break;
    }
    snprintf(out + pos, 4096 - pos, "]");
    mysql_free_result(res);
    return out;
}

static char *group_system_events_json(long long cid, int viewer_uid)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) {
        char *empty = (char *)malloc(3);
        if (empty) strcpy(empty, "[]");
        return empty;
    }
    char q[4096];
    snprintf(q, sizeof(q),
             "SELECT gse.id,gse.event_type,gse.actor_id,"
             " COALESCE(actor.username,''),gse.target_user_id,"
             " COALESCE(target.username,''),gse.role,gse.operation_id,"
             " gse.after_message_id,"
             " DATE_FORMAT(gse.created_at,'%%Y-%%m-%%d %%H:%%i:%%s'),"
             " COALESCE(gse.members_json,'[]')"
             " FROM group_system_events gse"
             " JOIN conversations c ON c.id=gse.conversation_id AND c.type='group'"
             " JOIN conversation_members cm"
             "   ON cm.conversation_id=gse.conversation_id AND cm.user_id=%d"
             " LEFT JOIN users actor ON actor.id=gse.actor_id"
             " LEFT JOIN users target ON target.id=gse.target_user_id"
             " WHERE gse.conversation_id=%lld"
             "   AND (gse.created_at >= cm.joined_at"
             "        OR gse.target_user_id=%d OR gse.actor_id=%d)"
             " ORDER BY gse.after_message_id ASC, gse.id ASC LIMIT 200",
             viewer_uid, cid, viewer_uid, viewer_uid);
    if (mysql_query(conn, q)) {
        db_pool_release(conn);
        char *empty = (char *)malloc(3);
        if (empty) strcpy(empty, "[]");
        return empty;
    }
    MYSQL_RES *res = mysql_store_result(conn);
    db_pool_release(conn);
    if (!res) {
        char *empty = (char *)malloc(3);
        if (empty) strcpy(empty, "[]");
        return empty;
    }

    const size_t cap = 256 * 1024;
    char *out = (char *)malloc(cap);
    if (!out) { mysql_free_result(res); return NULL; }
    size_t pos = (size_t)snprintf(out, cap, "[");
    MYSQL_ROW row;
    int first = 1;
    while ((row = mysql_fetch_row(res))) {
        char et[80], actor[130], target[130], role[40], op[160], ts[40];
        json_esc(row[1] ? row[1] : "", et, sizeof(et));
        json_esc(row[3] ? row[3] : "", actor, sizeof(actor));
        json_esc(row[5] ? row[5] : "", target, sizeof(target));
        json_esc(row[6] ? row[6] : "", role, sizeof(role));
        json_esc(row[7] ? row[7] : "", op, sizeof(op));
        json_esc(row[9] ? row[9] : "", ts, sizeof(ts));
        const char *members = (row[10] && row[10][0]) ? row[10] : "[]";
        const char *event_type = row[1] ? row[1] : "";
        const char *operation = "";
        if (strcmp(event_type, "member_added") == 0) operation = "add_member";
        else if (strcmp(event_type, "member_left") == 0) operation = "leave_group";
        else if (strcmp(event_type, "member_removed") == 0) operation = "remove_member";
        else if (strcmp(event_type, "member_role_changed") == 0) operation = "set_member_role";
        else if (strcmp(event_type, "group_info_updated") == 0) operation = "update_group_info";
        size_t need = strlen(members) + 1024;
        if (pos + need >= cap) break;
        pos += (size_t)snprintf(out + pos, cap - pos,
            "%s{\"id\":%s,\"system_event_id\":%s,"
            "\"event_type\":\"%s\",\"type\":\"%s\","
            "\"actor_id\":%s,\"by_user_id\":%s,\"by_username\":\"%s\","
            "\"target_user_id\":%s,\"user_id\":%s,\"username\":\"%s\","
            "\"role\":\"%s\",\"operation\":\"%s\","
            "\"operation_id\":\"%s\",\"after_message_id\":%s,"
            "\"time\":\"%s\",\"event_time\":\"%s\",\"members\":%s}",
            first ? "" : ",",
            row[0] ? row[0] : "0",
            row[0] ? row[0] : "0",
            et, et,
            row[2] ? row[2] : "0",
            row[2] ? row[2] : "0",
            actor,
            row[4] ? row[4] : "0",
            row[4] ? row[4] : "0",
            target,
            role,
            operation,
            op,
            row[8] ? row[8] : "0",
            ts, ts,
            members);
        first = 0;
    }
    snprintf(out + pos, cap - pos, "]");
    mysql_free_result(res);
    return out;
}

/* send_message: nhận ciphertext từ client, lưu DB và broadcast cho member. */

static void handle_send_message(int idx, const char *buf)
{
    uint64_t t0 = metrics_now_us();

    int conv_id_i = 0;
    jget_int(buf, "conversation_id", &conv_id_i);
    if (conv_id_i <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid conversation_id\"}");
        return;
    }
    long long cid = (long long)conv_id_i;

    size_t buf_len = strlen(buf);
    char *body = (char *)calloc(buf_len + 1, 1);
    if (!body) return;
    jget(buf, "body", body, (int)(buf_len + 1));

    if (!domain_validate_message_body(body, MAX_ENCRYPTED_MESSAGE_BODY)) {
        free(body);
        metrics_validation_error();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Message body is empty or too large\"}");
        return;
    }

    /* Cưỡng chế E2EE ở biên server: chỉ cho phép wire-format SecChat.
     * Server không biết body giải mã ra gì, nhưng có thể chặn plaintext hoặc
     * format đã bị gỡ bỏ. */
    if (!domain_validate_e2e_prefix(body)) {
        free(body);
        metrics_validation_error();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Unsupported or unsupported encrypted message\"}");
        return;
    }

    int my_uid = clients_get_uid(idx);

    int reply_to = 0;
    jget_int(buf, "reply_to_message_id", &reply_to);

    int mentions[50] = {0};
    int n_mentions = jget_array(buf, "mentions", mentions, 50);

    if (!conv_is_member(cid, my_uid)) {
        free(body);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member of this conversation\"}");
        return;
    }
    if (conv_is_disbanded(cid)) {
        free(body);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Group has been disbanded\"}");
        return;
    }

    if (!ratelimit_check(my_uid)) {
        free(body);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Rate limit exceeded — slow down\"}");
        return;
    }

    /* Với DM, nếu một trong hai bên block người kia thì không cho gửi tiếp. */
    {
        MYSQL *bc = db_pool_acquire();
        if (bc) {
            char bq[256];
            snprintf(bq, sizeof(bq),
                     "SELECT type FROM conversations WHERE id=%lld LIMIT 1", cid);
            char conv_type[16] = {0};
            if (mysql_query(bc, bq) == 0) {
                MYSQL_RES *br = mysql_store_result(bc);
                if (br) {
                    MYSQL_ROW brow = mysql_fetch_row(br);
                    if (brow && brow[0])
                        strncpy(conv_type, brow[0], sizeof(conv_type) - 1);
                    mysql_free_result(br);
                }
            }
            db_pool_release(bc);
            if (strcmp(conv_type, "direct") == 0) {
                int members[2] = {0};
                int nm = conv_get_members(cid, members, 2);
                for (int mi = 0; mi < nm; mi++) {
                    if (members[mi] != my_uid && block_either(my_uid, members[mi])) {
                        free(body);
                        clients_send(idx, "{\"type\":\"error\","
                                         "\"msg\":\"Cannot send message (blocked)\"}");
                        return;
                    }
                }
            }
        }
    }

    /* __KEM_INIT__ thuộc protocol cũ và đã bị validation chặn. Nhánh này chỉ là
     * guard phòng trường hợp binary/test cũ lọt qua, không phải flow chính. */
    if (strcmp(body, "__KEM_INIT__") == 0) {
        char uname[USERNAME_LEN];
        clients_get_username(idx, uname);
        char ts[24]; now_ts(ts, sizeof(ts));
        char msg_json[512];
        snprintf(msg_json, sizeof(msg_json),
                 "{\"type\":\"message\",\"conversation_id\":%lld,"
                 "\"from_id\":%d,\"from\":\"%s\","
                 "\"body\":\"__KEM_INIT__\",\"time\":\"%s\"}",
                 cid, my_uid, uname, ts);
        clients_broadcast_conv(cid, msg_json);
        free(body);
        return;
    }

    /* Lưu ciphertext vào DB. Với reply/edit metadata, server chỉ biết id tham
     * chiếu; nội dung body vẫn là ciphertext. */
    long long msg_id;
    if (reply_to > 0) {
        MYSQL *conn = db_pool_acquire();
        if (!conn) { free(body); return; }

        const char *ins_sql =
            "INSERT INTO messages"
            "(conversation_id, sender_id, body, reply_to_message_id)"
            " VALUES(?, ?, ?, ?)";
        MYSQL_STMT *s = mysql_stmt_init(conn);
        if (!s) { db_pool_release(conn); free(body); return; }
        if (mysql_stmt_prepare(s, ins_sql, (unsigned long)strlen(ins_sql))) {
            log_warn("messaging: msg_insert_reply prepare: %s", mysql_stmt_error(s));
            mysql_stmt_close(s); db_pool_release(conn); free(body);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to send message\"}");
            return;
        }
        MYSQL_BIND mb[4];
        memset(mb, 0, sizeof(mb));
        unsigned long body_ul = (unsigned long)strlen(body);
        mb[0].buffer_type   = MYSQL_TYPE_LONGLONG; mb[0].buffer = &cid;
        mb[1].buffer_type   = MYSQL_TYPE_LONG;     mb[1].buffer = &my_uid;
        mb[2].buffer_type   = MYSQL_TYPE_BLOB;
        mb[2].buffer        = (void *)body;
        mb[2].buffer_length = body_ul;
        mb[2].length        = &body_ul;
        mb[3].buffer_type   = MYSQL_TYPE_LONG;     mb[3].buffer = &reply_to;
        if (mysql_stmt_bind_param(s, mb) || mysql_stmt_execute(s)) {
            log_warn("messaging: msg_insert_reply exec: %s", mysql_stmt_error(s));
            mysql_stmt_close(s); db_pool_release(conn); free(body);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to send message\"}");
            return;
        }
        msg_id = (long long)mysql_stmt_insert_id(s);
        mysql_stmt_close(s);
        db_pool_release(conn);
    } else {
        msg_id = msg_insert(cid, my_uid, body);
        if (msg_id < 0) {
            free(body);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to send message\"}");
            return;
        }
    }

    metrics_msg_sent();
    conv_touch(cid);
    conv_reset_hidden(cid);

    /* Tạo payload broadcast. Body phải được JSON-escape vì là ciphertext dạng
     * string do client gửi lên. */
    size_t body_len = strlen(body);
    size_t esc_sz   = body_len * 2 + 4;
    char  *esc_body = (char *)malloc(esc_sz);
    if (!esc_body) { free(body); return; }
    json_esc(body, esc_body, (int)esc_sz);
    free(body);

    char uname[USERNAME_LEN];
    clients_get_username(idx, uname);
    char ts[24]; now_ts(ts, sizeof(ts));

    size_t msg_sz   = strlen(esc_body) + 512;
    char  *msg_json = (char *)malloc(msg_sz);
    if (!msg_json) { free(esc_body); return; }

    if (reply_to > 0) {
        snprintf(msg_json, msg_sz,
                 "{\"type\":\"message\",\"id\":%lld,\"conversation_id\":%lld,"
                 "\"from_id\":%d,\"from\":\"%s\",\"body\":\"%s\","
                 "\"reply_to_message_id\":%d,\"time\":\"%s\"}",
                 msg_id, cid, my_uid, uname, esc_body, reply_to, ts);
    } else {
        snprintf(msg_json, msg_sz,
                 "{\"type\":\"message\",\"id\":%lld,\"conversation_id\":%lld,"
                 "\"from_id\":%d,\"from\":\"%s\",\"body\":\"%s\",\"time\":\"%s\"}",
                 msg_id, cid, my_uid, uname, esc_body, ts);
    }
    free(esc_body);

    clients_broadcast_conv(cid, msg_json);

    /* Nếu member offline, lưu nguyên event ciphertext vào notification queue để
     * flush lại khi họ đăng nhập. */
    {
        int conv_members[64];
        int nm = conv_get_members(cid, conv_members, 64);
        for (int mi = 0; mi < nm; mi++) {
            int muid = conv_members[mi];
            if (muid == my_uid) continue;
            if (!clients_is_online(muid))
                notif_enqueue(muid, "message", msg_json);
        }
    }

    free(msg_json);

    /* Mention chỉ chứa metadata id; nội dung thật vẫn nằm trong ciphertext. */
    for (int mi = 0; mi < n_mentions; mi++) {
        int muid = mentions[mi];
        if (muid <= 0 || muid == my_uid) continue;
        if (!conv_is_member(cid, muid)) continue;
        char mn[256];
        snprintf(mn, sizeof(mn),
                 "{\"type\":\"mention_notification\","
                 "\"conversation_id\":%lld,"
                 "\"from_id\":%d,\"from\":\"%s\","
                 "\"message_id\":%lld}",
                 cid, my_uid, uname, msg_id);
        clients_send_to_uid(muid, mn);
    }

    metrics_lat_msg_us(metrics_now_us() - t0);
}

/* ── history ─────────────────────────────────────────────────────────────── */

static void handle_get_history(int idx, const char *buf)
{
    /* Server kiểm tra membership trước khi trả history. History vẫn là
     * ciphertext; client tự decrypt và tự kiểm tra transcript consistency. */
    int conv_id_i = 0;
    jget_int(buf, "conversation_id", &conv_id_i);
    if (conv_id_i <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid conversation_id\"}");
        return;
    }
    long long cid   = (long long)conv_id_i;
    int my_uid      = clients_get_uid(idx);

    if (!conv_is_member(cid, my_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}");
        return;
    }

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;

    char q[512];
    snprintf(q, sizeof(q),
             "SELECT m.id, m.sender_id, u.username, m.body,"
             " m.sent_at, m.edited_at, m.deleted_at, m.reply_to_message_id,"
             " m.edit_target_message_id, m.forwarded_from_id"
             " FROM messages m"
             " JOIN users u ON m.sender_id=u.id"
             " JOIN conversations c ON c.id=m.conversation_id"
             " JOIN conversation_members cm"
             "   ON cm.conversation_id=m.conversation_id AND cm.user_id=%d"
             " WHERE m.conversation_id=%lld"
             "   AND (c.type!='group' OR m.sent_at >= cm.joined_at)"
             " ORDER BY m.sent_at DESC, m.id DESC LIMIT 100",
             my_uid, cid);
    if (mysql_query(conn, q)) {
        db_pool_release(conn);
        return;
    }
    MYSQL_RES *res = mysql_store_result(conn);
    db_pool_release(conn);
    if (!res) return;

    int       nrows  = (int)mysql_num_rows(res);
    MYSQL_ROW *rows  = (MYSQL_ROW *)malloc(sizeof(MYSQL_ROW) * (size_t)(nrows > 0 ? nrows : 1));
    if (!rows) { mysql_free_result(res); return; }
    for (int i = 0; i < nrows; i++) rows[i] = mysql_fetch_row(res);

    char *system_events = group_system_events_json(cid, my_uid);
    if (!system_events) {
        system_events = (char *)malloc(3);
        if (system_events) strcpy(system_events, "[]");
    }

    size_t total = 128;
    for (int i = 0; i < nrows; i++) {
        int is_del = (rows[i][6] != NULL);
        const char *b = is_del ? "" : (rows[i][3] ? rows[i][3] : "");
        total += strlen(b) * 2 + 4600;
    }
    total += system_events ? strlen(system_events) + 64 : 64;

    char *out = (char *)malloc(total);
    if (!out) {
        if (system_events) free(system_events);
        free(rows);
        mysql_free_result(res);
        return;
    }

    size_t pos = (size_t)snprintf(out, total,
        "{\"type\":\"history\",\"conversation_id\":%lld,\"messages\":[", cid);

    int first = 1;
    for (int i = nrows - 1; i >= 0; i--) {
        int is_deleted = (rows[i][6] != NULL);
        int is_edited  = (rows[i][5] != NULL && !is_deleted);
        const char *body_to_use = is_deleted ? "" : (rows[i][3] ? rows[i][3] : "");

        size_t body_len = strlen(body_to_use);
        size_t eb_size  = body_len * 2 + 16;
        char  *eb = (char *)malloc(eb_size);
        if (!eb) continue;
        char eu[130];
        json_esc(body_to_use, eb, (int)eb_size);
        json_esc(rows[i][2] ? rows[i][2] : "", eu, sizeof(eu));

        if (!first) pos += (size_t)snprintf(out + pos, total - pos, ",");
        first = 0;

        long long msg_id_ll = rows[i][0] ? atoll(rows[i][0]) : 0;
        char *reactions = message_reactions_json(msg_id_ll, my_uid);
        int pinned = message_is_pinned(cid, msg_id_ll);
        pos += (size_t)snprintf(out + pos, total - pos,
            "{\"id\":%s,\"sender_id\":%s,\"sender\":\"%s\","
            "\"body\":\"%s\",\"time\":\"%s\","
            "\"edited\":%s,\"deleted\":%s,"
            "\"pinned\":%s,\"reactions\":%s",
            rows[i][0], rows[i][1], eu, eb, rows[i][4],
            is_edited  ? "true" : "false",
            is_deleted ? "true" : "false",
            pinned ? "true" : "false",
            reactions ? reactions : "[]");
        const char *reply_to_str = rows[i][7];
        if (reply_to_str && reply_to_str[0])
            pos += (size_t)snprintf(out + pos, total - pos,
                                    ",\"reply_to_message_id\":%s", reply_to_str);
        const char *edit_target_str = rows[i][8];
        if (edit_target_str && edit_target_str[0])
            pos += (size_t)snprintf(out + pos, total - pos,
                                    ",\"edit_target_message_id\":%s", edit_target_str);
        const char *forwarded_str = rows[i][9];
        if (forwarded_str && forwarded_str[0])
            pos += (size_t)snprintf(out + pos, total - pos,
                                    ",\"forwarded_from_id\":%s", forwarded_str);
        pos += (size_t)snprintf(out + pos, total - pos, "}");
        if (reactions) free(reactions);
        free(eb);
    }
    snprintf(out + pos, total - pos, "],\"system_events\":%s}",
             system_events ? system_events : "[]");
    if (system_events) free(system_events);
    free(rows);
    mysql_free_result(res);
    clients_send(idx, out);
    free(out);
}

/* ── inbox ───────────────────────────────────────────────────────────────── */

static void handle_get_inbox(int idx)
{
    /* Inbox trả ciphertext prefix của message mới nhất. Client sẽ thay preview
     * bằng plaintext từ cache nếu đã từng giải mã message đó. Self-DM/Saved
     * Messages đã bị gỡ khỏi sản phẩm nên các direct row không có peer sẽ bị bỏ
     * qua để tránh tạo conversation khó hiểu trong UI. */
    int my_uid = clients_get_uid(idx);

    MYSQL *conn = db_pool_acquire();
    if (!conn) return;

    char q[4096];
    snprintf(q, sizeof(q),
        "SELECT c.id, c.type, c.name, c.last_message_at,"
        " u2.id, u2.username,"
        " CASE WHEN u2.privacy_online='nobody' THEN 'offline' ELSE u2.status END,"
        " CASE WHEN u2.privacy_last_seen='nobody' THEN ''"
        "      ELSE DATE_FORMAT(u2.last_seen, '%%Y-%%m-%%d %%H:%%i:%%s') END,"
        " (SELECT LEFT(body,%d) FROM messages"
        "  WHERE conversation_id=c.id AND deleted_at IS NULL"
        "  AND (c.type!='group' OR sent_at >= cm1.joined_at)"
        "  AND (body LIKE 'S3DR:%%'"
        "       OR body LIKE 'S3MLS:%%'"
        "       OR body LIKE 'FILE:%%')"
        "  ORDER BY sent_at DESC LIMIT 1) AS last_msg,"
        " (SELECT id FROM messages"
        "  WHERE conversation_id=c.id AND deleted_at IS NULL"
        "  AND (c.type!='group' OR sent_at >= cm1.joined_at)"
        "  AND (body LIKE 'S3DR:%%'"
        "       OR body LIKE 'S3MLS:%%'"
        "       OR body LIKE 'FILE:%%')"
        "  ORDER BY sent_at DESC LIMIT 1) AS last_msg_id,"
        " (SELECT sender_id FROM messages"
        "  WHERE conversation_id=c.id AND deleted_at IS NULL"
        "  AND (c.type!='group' OR sent_at >= cm1.joined_at)"
        "  AND (body LIKE 'S3DR:%%'"
        "       OR body LIKE 'S3MLS:%%'"
        "       OR body LIKE 'FILE:%%')"
        "  ORDER BY sent_at DESC LIMIT 1) AS last_sender_id,"
        " c.creator_id, c.is_disbanded,"
        " COALESCE(cm1.last_read_message_id,0),"
        " (SELECT COUNT(*) FROM messages"
        "  WHERE conversation_id=c.id AND deleted_at IS NULL"
        "  AND (c.type!='group' OR sent_at >= cm1.joined_at)"
        "  AND id > COALESCE(cm1.last_read_message_id,0)"
        "  AND sender_id!=%d"
        "  AND (body LIKE 'S3DR:%%'"
        "       OR body LIKE 'S3MLS:%%'"
        "       OR body LIKE 'FILE:%%')) AS unread_count,"
        " cm1.muted_until, cm1.archived_at, cm1.conv_pinned_at,"
        " COALESCE(cm1.force_unread,0), c.disappear_after_secs"
        " FROM conversations c"
        " JOIN conversation_members cm1"
        "   ON c.id=cm1.conversation_id AND cm1.user_id=%d"
        " LEFT JOIN conversation_members cm2"
        "   ON (c.type='direct' AND c.id=cm2.conversation_id AND cm2.user_id!=%d)"
        " LEFT JOIN users u2 ON cm2.user_id=u2.id"
        " WHERE (cm1.hidden_at IS NULL OR c.last_message_at > cm1.hidden_at)"
        " ORDER BY c.last_message_at DESC LIMIT 50",
        MAX_INBOX_WIRE_PREVIEW, my_uid, my_uid, my_uid);

    if (mysql_query(conn, q)) {
        db_pool_release(conn);
        return;
    }
    MYSQL_RES *res = mysql_store_result(conn);
    db_pool_release(conn);
    if (!res) return;

    char *out = (char *)malloc(INBOX_JSON_CAP);
    if (!out) { mysql_free_result(res); return; }

    size_t pos = (size_t)snprintf(out, INBOX_JSON_CAP,
        "{\"type\":\"inbox\",\"conversations\":[");
    MYSQL_ROW row;
    int first = 1;
    while ((row = mysql_fetch_row(res))) {
        char esc_msg[MAX_INBOX_WIRE_PREVIEW * 2 + 16];
        json_esc(row[8] ? row[8] : "", esc_msg, sizeof(esc_msg));
        int unread_i = row[14] ? atoi(row[14]) : 0;
        int force_unread = row[18] ? atoi(row[18]) : 0;
        const char *unread = (unread_i > 0 || force_unread > 0) ? "1" : "0";
        const char *muted = row[15] ? "true" : "false";
        const char *archived = row[16] ? "true" : "false";
        const char *conv_pinned = row[17] ? "true" : "false";
        const char *disappear = row[19] ? row[19] : "null";
        if (pos + (MAX_INBOX_WIRE_PREVIEW * 2 + 1024) >= INBOX_JSON_CAP)
            break;
        const char *comma = first ? "" : ",";

        if (row[1] && strcmp(row[1], "group") == 0) {
            /* Group không có other_id vì membership có thể nhiều người. */
            char esc_name[210];
            json_esc(row[2] ? row[2] : "Unnamed Group", esc_name, sizeof(esc_name));
            pos += (size_t)snprintf(out + pos, INBOX_JSON_CAP - pos,
                "%s{\"conversation_id\":%s,\"type\":\"group\",\"name\":\"%s\","
                "\"last_message\":\"%s\",\"last_message_at\":\"%s\","
                "\"last_message_id\":%s,\"last_sender_id\":%s,"
                "\"creator_id\":%s,\"is_disbanded\":%s,"
                "\"unread_count\":%s,\"muted\":%s,\"archived\":%s,"
                "\"pinned_conversation\":%s,\"force_unread\":%s,"
                "\"disappear_after_secs\":%s,\"is_group\":true}",
                comma, row[0], esc_name, esc_msg, row[3] ? row[3] : "",
                row[9] ? row[9] : "0",
                row[10] ? row[10] : "0",
                row[11] ? row[11] : "null",
                (row[12] && atoi(row[12])) ? "true" : "false",
                unread, muted, archived, conv_pinned,
                force_unread > 0 ? "true" : "false", disappear);
            first = 0;
        } else if (row[4] && row[5]) {
            /* DM thường: other_id là peer để client map safety/audit state. */
            pos += (size_t)snprintf(out + pos, INBOX_JSON_CAP - pos,
                "%s{\"conversation_id\":%s,\"type\":\"direct\",\"other_id\":%s,"
                "\"username\":\"%s\",\"status\":\"%s\",\"last_seen\":\"%s\","
                "\"last_message\":\"%s\",\"last_message_at\":\"%s\","
                "\"last_message_id\":%s,\"last_sender_id\":%s,"
                "\"unread_count\":%s,\"muted\":%s,\"archived\":%s,"
                "\"pinned_conversation\":%s,\"force_unread\":%s,"
                "\"disappear_after_secs\":%s,\"is_group\":false}",
                comma, row[0], row[4], row[5], row[6] ? row[6] : "offline",
                row[7] ? row[7] : "",
                esc_msg, row[3] ? row[3] : "",
                row[9] ? row[9] : "0",
                row[10] ? row[10] : "0",
                unread, muted, archived, conv_pinned,
                force_unread > 0 ? "true" : "false", disappear);
            first = 0;
        }
    }
    snprintf(out + pos, INBOX_JSON_CAP - pos, "]}");
    mysql_free_result(res);
    clients_send(idx, out);
    free(out);
}

/* ── start_dm ─────────────────────────────────────────────────────────────── */

static void handle_start_dm(int idx, const char *buf)
{
    /* Khóa DM được thiết lập sau đó bằng PQXDH ở client. Server chỉ tạo row
     * conversation và trả conv_id/with_user_id. */
    int my_uid    = clients_get_uid(idx);
    int other_uid = 0;
    jget_int(buf, "user_id", &other_uid);

    if (other_uid <= 0 || other_uid == my_uid) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Saved Messages is no longer supported\"}");
        return;
    }

    if (!friendship_exists_accepted(my_uid, other_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Can only DM friends\"}");
        return;
    }

    if (block_either(my_uid, other_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Cannot start conversation (blocked)\"}");
        return;
    }

    long long conv_id = conv_find_or_create_dm(my_uid, other_uid);
    if (conv_id < 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to create DM\"}");
        return;
    }

    char resp[128];
    snprintf(resp, sizeof(resp),
             "{\"type\":\"dm_ready\",\"conversation_id\":%lld,\"with_user_id\":%d}",
             conv_id, other_uid);
    clients_send(idx, resp);
}

/* ── edit_message ────────────────────────────────────────────────────────── */

static void handle_edit_message(int idx, const char *buf)
{
    /* Không ghi đè ciphertext của message gốc. Client gửi ciphertext mới,
     * server chỉ kiểm tra sender có quyền edit message gốc rồi append event có
     * edit_target_message_id. Nhờ vậy ratchet không bị lệch và history replay
     * vẫn theo thứ tự event. */
    int my_uid   = clients_get_uid(idx);
    int msg_id_i = 0;
    jget_int(buf, "message_id", &msg_id_i);
    if (msg_id_i <= 0) return;

    long long msg_id = (long long)msg_id_i;
    size_t buf_len   = strlen(buf);
    char  *new_body  = (char *)calloc(buf_len + 1, 1);
    if (!new_body) return;
    jget(buf, "new_body", new_body, (int)(buf_len + 1));

    if (!domain_validate_message_body(new_body, MAX_ENCRYPTED_MESSAGE_BODY)) {
        free(new_body);
        metrics_validation_error();
        clients_send(idx,
            "{\"type\":\"error\",\"msg\":\"Message body is empty or too large\"}");
        return;
    }

    if (!domain_validate_e2e_prefix(new_body)) {
        free(new_body);
        metrics_validation_error();
        clients_send(idx,
            "{\"type\":\"error\",\"msg\":\"Unsupported or unsupported encrypted message\"}");
        return;
    }

    long long cid = msg_get_editable_conv_id(msg_id, my_uid);
    if (cid < 0) {
        free(new_body);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Cannot edit this message\"}");
        return;
    }

    long long edit_id = msg_insert_edit_event(cid, my_uid, new_body, msg_id);
    if (edit_id < 0) {
        free(new_body);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to edit message\"}");
        return;
    }

    size_t body_len  = strlen(new_body);
    size_t esc_sz    = body_len * 2 + 4;
    char  *esc_body  = (char *)malloc(esc_sz);
    if (!esc_body) { free(new_body); return; }
    json_esc(new_body, esc_body, (int)esc_sz);
    free(new_body);

    char ts[24];
    now_ts(ts, sizeof(ts));
    char uname[USERNAME_LEN];
    clients_get_username(idx, uname);

    size_t notif_sz = esc_sz + 384;
    char  *notif    = (char *)malloc(notif_sz);
    if (!notif) { free(esc_body); return; }
    snprintf(notif, notif_sz,
             "{\"type\":\"message\",\"id\":%lld,\"conversation_id\":%lld,"
             "\"from_id\":%d,\"from\":\"%s\",\"body\":\"%s\","
             "\"edit_target_message_id\":%lld,\"time\":\"%s\"}",
             edit_id, cid, my_uid, uname, esc_body, msg_id, ts);
    free(esc_body);
    metrics_msg_edited();
    conv_touch(cid);
    conv_reset_hidden(cid);
    clients_broadcast_conv(cid, notif);

    {
        int conv_members[64];
        int nm = conv_get_members(cid, conv_members, 64);
        for (int mi = 0; mi < nm; mi++) {
            int muid = conv_members[mi];
            if (muid == my_uid) continue;
            if (!clients_is_online(muid))
                notif_enqueue(muid, "message", notif);
        }
    }

    free(notif);
}

/* ── delete_message ──────────────────────────────────────────────────────── */

static void handle_delete_message(int idx, const char *buf)
{
    /* Soft delete chỉ là metadata. Server không cần và không thể giải mã body. */
    int my_uid   = clients_get_uid(idx);
    int msg_id_i = 0;
    jget_int(buf, "message_id", &msg_id_i);
    if (msg_id_i <= 0) return;

    long long msg_id = (long long)msg_id_i;
    long long cid    = msg_get_conv_id(msg_id);
    if (cid < 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Message not found\"}");
        return;
    }

    if (!msg_soft_delete(msg_id, my_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Cannot delete this message\"}");
        return;
    }

    char notif[128];
    snprintf(notif, sizeof(notif),
             "{\"type\":\"message_deleted\",\"id\":%lld,\"conversation_id\":%lld}",
             msg_id, cid);
    metrics_msg_deleted();
    clients_broadcast_conv(cid, notif);
}

/* ── typing indicators ────────────────────────────────────────────────────── */

static void handle_typing(int idx, const char *buf, int is_start)
{
    /* Typing indicator là metadata tùy chọn, không ảnh hưởng tới E2EE body. */
    int my_uid    = clients_get_uid(idx);
    int conv_id_i = 0;
    jget_int(buf, "conversation_id", &conv_id_i);
    if (conv_id_i <= 0) return;
    long long cid = (long long)conv_id_i;

    if (!conv_is_member(cid, my_uid)) return;

    char uname[USERNAME_LEN];
    clients_get_username(idx, uname);

    char notif[256];
    snprintf(notif, sizeof(notif),
             "{\"type\":\"%s\",\"conversation_id\":%lld,"
             "\"from_id\":%d,\"from\":\"%s\"}",
             is_start ? "typing_start" : "typing_stop",
             cid, my_uid, uname);

    int uids[200];
    int n = conv_get_members(cid, uids, 200);
    for (int i = 0; i < n; i++) {
        if (uids[i] != my_uid)
            clients_send_to_uid(uids[i], notif);
    }
}

/* ── dispatcher ──────────────────────────────────────────────────────────── */

int messaging_dispatch(int idx, const char *type, const char *buf)
{
    /* Trả 1 nếu command thuộc messaging service, 0 để dispatcher cấp cao thử
     * các service khác. */
    if (strcmp(type, "message") == 0) {
        handle_send_message(idx, buf);
        return 1;
    }
    if (strcmp(type, "history") == 0) {
        handle_get_history(idx, buf);
        return 1;
    }
    if (strcmp(type, "get_inbox") == 0) {
        handle_get_inbox(idx);
        return 1;
    }
    if (strcmp(type, "start_dm") == 0) {
        handle_start_dm(idx, buf);
        return 1;
    }
    if (strcmp(type, "edit_message") == 0) {
        handle_edit_message(idx, buf);
        return 1;
    }
    if (strcmp(type, "delete_message") == 0) {
        handle_delete_message(idx, buf);
        return 1;
    }
    if (strcmp(type, "typing_start") == 0) {
        handle_typing(idx, buf, 1);
        return 1;
    }
    if (strcmp(type, "typing_stop") == 0) {
        handle_typing(idx, buf, 0);
        return 1;
    }
    return 0;
}
