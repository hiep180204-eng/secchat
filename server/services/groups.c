/*
 * services/groups.c — bounded context quản lý nhóm.
 *
 * Mọi thay đổi nhóm phía server đi qua quy trình hai bước prepare/apply của
 * OpenMLS: server kiểm policy, lưu lại bytes Commit/Welcome/GroupInfo/control,
 * rồi MỚI mutate membership hoặc metadata. Server không bao giờ tạo ra MLS
 * secret — nó chỉ validate public state và lưu/chuyển tiếp artifact.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <mysql/mysql.h>

#include "groups.h"
#include "clients.h"
#include "json_helpers.h"
#include "log.h"
#include "metrics.h"
#include "db_pool.h"
#include "friendship_repo.h"
#include "conversation_repo.h"
#include "user_repo.h"
#include "validation.h"
#include "notification_repo.h"
#include "cJSON.h"

#define SECCHAT_MLS_PQ_CIPHERSUITE "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"
#define SECCHAT_MLS_VALIDATION_BACKEND "openmls-public-group"

typedef struct GroupSystemEventMeta {
    long long id;
    long long after_message_id;
    char event_time[32];
} GroupSystemEventMeta;

static void copy_username(char out[USERNAME_LEN], const char *in)
{
    if (!in) {
        out[0] = '\0';
        return;
    }
    size_t n = strnlen(in, USERNAME_LEN - 1);
    memcpy(out, in, n);
    out[n] = '\0';
}

static void escaped_username_for_uid(int uid, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (uid <= 0) return;
    char uname[USERNAME_LEN] = {0};
    UserRecord rec;
    if (user_repo_find_by_id(uid, &rec))
        copy_username(uname, rec.username);
    json_esc(uname, out, out_sz);
}

static const char *json_str_obj(cJSON *obj, const char *name)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    return (cJSON_IsString(item) && item->valuestring) ? item->valuestring : "";
}

static int json_int_obj(cJSON *obj, const char *name, int def)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    return cJSON_IsNumber(item) ? item->valueint : def;
}

static void make_operation_id(char out[65])
{
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        snprintf(out, 65, "%lld%06d", (long long)time(NULL), rand() & 0xffffff);
        return;
    }
    for (size_t i = 0; i < sizeof(raw); i++)
        snprintf(out + i * 2, 3, "%02x", raw[i]);
    out[32] = '\0';
}

static int store_pending_op(const char *operation_id, long long cid, int actor_id,
                            const char *operation, int target_uid,
                            const char *role, const char *details_json)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    const char *sql =
        "INSERT INTO mls_pending_group_ops"
        "(operation_id,conversation_id,actor_id,operation,target_user_id,"
        " role,details_json,expires_at)"
        " VALUES(?,?,?,?,?,?,?,DATE_ADD(NOW(3), INTERVAL 10 MINUTE))";
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt) { db_pool_release(conn); return 0; }
    if (mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql))) {
        log_warn("store_pending_op prepare: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt); db_pool_release(conn); return 0;
    }
    MYSQL_BIND b[7];
    memset(b, 0, sizeof(b));
    unsigned long opid_len = (unsigned long)strlen(operation_id);
    unsigned long op_len = (unsigned long)strlen(operation);
    unsigned long role_len = (unsigned long)(role ? strlen(role) : 0);
    unsigned long details_len = (unsigned long)(details_json ? strlen(details_json) : 0);
    b[0].buffer_type = MYSQL_TYPE_STRING; b[0].buffer = (void *)operation_id;
    b[0].buffer_length = opid_len; b[0].length = &opid_len;
    b[1].buffer_type = MYSQL_TYPE_LONGLONG; b[1].buffer = &cid;
    b[2].buffer_type = MYSQL_TYPE_LONG; b[2].buffer = &actor_id;
    b[3].buffer_type = MYSQL_TYPE_STRING; b[3].buffer = (void *)operation;
    b[3].buffer_length = op_len; b[3].length = &op_len;
    if (target_uid > 0) {
        b[4].buffer_type = MYSQL_TYPE_LONG; b[4].buffer = &target_uid;
    } else {
        b[4].buffer_type = MYSQL_TYPE_NULL;
    }
    if (role && role[0]) {
        b[5].buffer_type = MYSQL_TYPE_STRING; b[5].buffer = (void *)role;
        b[5].buffer_length = role_len; b[5].length = &role_len;
    } else {
        b[5].buffer_type = MYSQL_TYPE_NULL;
    }
    if (details_json && details_json[0]) {
        b[6].buffer_type = MYSQL_TYPE_STRING; b[6].buffer = (void *)details_json;
        b[6].buffer_length = details_len; b[6].length = &details_len;
    } else {
        b[6].buffer_type = MYSQL_TYPE_NULL;
    }
    int ok = !(mysql_stmt_bind_param(stmt, b) || mysql_stmt_execute(stmt));
    if (!ok) log_warn("store_pending_op exec: %s", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    db_pool_release(conn);
    return ok;
}

static int store_mls_handshake(long long cid, int sender_id, int target_uid,
                               const char *kind, long long epoch,
                               const char *operation_id,
                               const char *mls_message_b64)
{
    if (!kind || !kind[0] || !mls_message_b64 || !mls_message_b64[0])
        return 1;
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    const char *sql =
        "INSERT INTO mls_group_handshake"
        "(conversation_id,sender_id,target_user_id,kind,epoch,operation_id,"
        " mls_message_b64) VALUES(?,?,?,?,?,?,?)";
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt) { db_pool_release(conn); return 0; }
    if (mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql))) {
        mysql_stmt_close(stmt); db_pool_release(conn); return 0;
    }
    MYSQL_BIND b[7];
    memset(b, 0, sizeof(b));
    unsigned long kind_len = (unsigned long)strlen(kind);
    unsigned long opid_len = (unsigned long)(operation_id ? strlen(operation_id) : 0);
    unsigned long msg_len = (unsigned long)strlen(mls_message_b64);
    b[0].buffer_type = MYSQL_TYPE_LONGLONG; b[0].buffer = &cid;
    b[1].buffer_type = MYSQL_TYPE_LONG; b[1].buffer = &sender_id;
    if (target_uid > 0) {
        b[2].buffer_type = MYSQL_TYPE_LONG; b[2].buffer = &target_uid;
    } else {
        b[2].buffer_type = MYSQL_TYPE_NULL;
    }
    b[3].buffer_type = MYSQL_TYPE_STRING; b[3].buffer = (void *)kind;
    b[3].buffer_length = kind_len; b[3].length = &kind_len;
    b[4].buffer_type = MYSQL_TYPE_LONGLONG; b[4].buffer = &epoch;
    if (operation_id && operation_id[0]) {
        b[5].buffer_type = MYSQL_TYPE_STRING; b[5].buffer = (void *)operation_id;
        b[5].buffer_length = opid_len; b[5].length = &opid_len;
    } else {
        b[5].buffer_type = MYSQL_TYPE_NULL;
    }
    b[6].buffer_type = MYSQL_TYPE_STRING; b[6].buffer = (void *)mls_message_b64;
    b[6].buffer_length = msg_len; b[6].length = &msg_len;
    int ok = !(mysql_stmt_bind_param(stmt, b) || mysql_stmt_execute(stmt));
    mysql_stmt_close(stmt);
    db_pool_release(conn);
    return ok;
}

static long long max_message_id_for_conv(long long cid)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    char q[192];
    snprintf(q, sizeof(q),
             "SELECT COALESCE(MAX(id),0) FROM messages WHERE conversation_id=%lld",
             cid);
    long long mid = 0;
    if (mysql_query(conn, q) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0]) mid = atoll(row[0]);
            mysql_free_result(res);
        }
    }
    db_pool_release(conn);
    return mid;
}

/* Ghi một system event của nhóm (thêm/bớt thành viên, đổi vai trò...) vào timeline
 * để thành viên thấy "X đã vào nhóm" / "Y bị xóa"... khi tải lại history. */
static GroupSystemEventMeta store_group_system_event(
    long long cid,
    const char *event_type,
    int actor_id,
    int target_uid,
    const char *role,
    const char *operation_id,
    const char *members_json)
{
    GroupSystemEventMeta meta;
    memset(&meta, 0, sizeof(meta));
    if (cid <= 0 || !event_type || !event_type[0] ||
        !operation_id || !operation_id[0])
        return meta;

    meta.after_message_id = max_message_id_for_conv(cid);
    MYSQL *conn = db_pool_acquire();
    if (!conn) return meta;

    const char *sql =
        "INSERT INTO group_system_events"
        "(conversation_id,event_type,actor_id,target_user_id,role,"
        " operation_id,after_message_id,members_json)"
        " VALUES(?,?,?,?,?,?,?,?)"
        " ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id),"
        " after_message_id=VALUES(after_message_id),"
        " members_json=VALUES(members_json)";
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt || mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql))) {
        if (stmt) mysql_stmt_close(stmt);
        db_pool_release(conn);
        return meta;
    }

    const char *role_s = role ? role : "";
    const char *members_s = members_json ? members_json : "[]";
    int actor_i = actor_id > 0 ? actor_id : 0;
    int target_i = target_uid > 0 ? target_uid : 0;
    unsigned long event_len = (unsigned long)strlen(event_type);
    unsigned long role_len = (unsigned long)strlen(role_s);
    unsigned long op_len = (unsigned long)strlen(operation_id);
    unsigned long members_len = (unsigned long)strlen(members_s);
    MYSQL_BIND b[8];
    memset(b, 0, sizeof(b));
    b[0].buffer_type = MYSQL_TYPE_LONGLONG; b[0].buffer = &cid;
    b[1].buffer_type = MYSQL_TYPE_STRING; b[1].buffer = (void *)event_type;
    b[1].buffer_length = event_len; b[1].length = &event_len;
    b[2].buffer_type = MYSQL_TYPE_LONG; b[2].buffer = &actor_i;
    b[3].buffer_type = MYSQL_TYPE_LONG; b[3].buffer = &target_i;
    b[4].buffer_type = MYSQL_TYPE_STRING; b[4].buffer = (void *)role_s;
    b[4].buffer_length = role_len; b[4].length = &role_len;
    b[5].buffer_type = MYSQL_TYPE_STRING; b[5].buffer = (void *)operation_id;
    b[5].buffer_length = op_len; b[5].length = &op_len;
    b[6].buffer_type = MYSQL_TYPE_LONGLONG; b[6].buffer = &meta.after_message_id;
    b[7].buffer_type = MYSQL_TYPE_STRING; b[7].buffer = (void *)members_s;
    b[7].buffer_length = members_len; b[7].length = &members_len;

    if (mysql_stmt_bind_param(stmt, b) == 0 && mysql_stmt_execute(stmt) == 0)
        meta.id = (long long)mysql_stmt_insert_id(stmt);
    else
        log_warn("store_group_system_event exec: %s", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);

    if (meta.id > 0) {
        char q[256];
        snprintf(q, sizeof(q),
                 "SELECT after_message_id,"
                 " DATE_FORMAT(created_at,'%%Y-%%m-%%d %%H:%%i:%%s')"
                 " FROM group_system_events WHERE id=%lld LIMIT 1",
                 meta.id);
        if (mysql_query(conn, q) == 0) {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row = mysql_fetch_row(res);
                if (row) {
                    if (row[0]) meta.after_message_id = atoll(row[0]);
                    if (row[1])
                        strncpy(meta.event_time, row[1],
                                sizeof(meta.event_time) - 1);
                }
                mysql_free_result(res);
            }
        }
    }

    db_pool_release(conn);
    return meta;
}

static void upsert_mls_group_state(long long cid, const char *group_id_b64,
                                   long long epoch, const char *commit_ref,
                                   const char *group_info_b64,
                                   const char *ciphersuite,
                                   const char *public_state_b64,
                                   const char *public_state_hash,
                                   const char *validation_backend)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    const char *gid = (group_id_b64 && group_id_b64[0]) ? group_id_b64 : "";
    const char *cref = (commit_ref && commit_ref[0]) ? commit_ref : "";
    const char *ginfo = (group_info_b64 && group_info_b64[0]) ? group_info_b64 : "";
    const char *cs = (ciphersuite && ciphersuite[0]) ? ciphersuite : SECCHAT_MLS_PQ_CIPHERSUITE;
    const char *pub = (public_state_b64 && public_state_b64[0]) ? public_state_b64 : "";
    const char *phash = (public_state_hash && public_state_hash[0]) ? public_state_hash : "";
    const char *backend = (validation_backend && validation_backend[0])
                        ? validation_backend : SECCHAT_MLS_VALIDATION_BACKEND;
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    const char *sql =
        "INSERT INTO mls_group_state"
        "(conversation_id,group_id_b64,epoch,last_commit_ref,last_group_info_b64,"
        " ciphersuite,public_state_b64,public_state_hash,validation_backend,validated_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,NOW(3))"
        " ON DUPLICATE KEY UPDATE epoch=VALUES(epoch),"
        " last_commit_ref=VALUES(last_commit_ref),"
        " last_group_info_b64=VALUES(last_group_info_b64),"
        " ciphersuite=VALUES(ciphersuite),"
        " public_state_b64=VALUES(public_state_b64),"
        " public_state_hash=VALUES(public_state_hash),"
        " validation_backend=VALUES(validation_backend),"
        " validated_at=NOW(3)";
    if (!stmt || mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql))) {
        if (stmt) mysql_stmt_close(stmt);
        db_pool_release(conn);
        return;
    }
    MYSQL_BIND b[9];
    memset(b, 0, sizeof(b));
    unsigned long gid_len = (unsigned long)strlen(gid);
    unsigned long cref_len = (unsigned long)strlen(cref);
    unsigned long ginfo_len = (unsigned long)strlen(ginfo);
    unsigned long cs_len = (unsigned long)strlen(cs);
    unsigned long pub_len = (unsigned long)strlen(pub);
    unsigned long phash_len = (unsigned long)strlen(phash);
    unsigned long backend_len = (unsigned long)strlen(backend);
    b[0].buffer_type = MYSQL_TYPE_LONGLONG; b[0].buffer = &cid;
    b[1].buffer_type = MYSQL_TYPE_STRING; b[1].buffer = (void *)gid;
    b[1].buffer_length = gid_len; b[1].length = &gid_len;
    b[2].buffer_type = MYSQL_TYPE_LONGLONG; b[2].buffer = &epoch;
    b[3].buffer_type = MYSQL_TYPE_STRING; b[3].buffer = (void *)cref;
    b[3].buffer_length = cref_len; b[3].length = &cref_len;
    b[4].buffer_type = MYSQL_TYPE_STRING; b[4].buffer = (void *)ginfo;
    b[4].buffer_length = ginfo_len; b[4].length = &ginfo_len;
    b[5].buffer_type = MYSQL_TYPE_STRING; b[5].buffer = (void *)cs;
    b[5].buffer_length = cs_len; b[5].length = &cs_len;
    b[6].buffer_type = MYSQL_TYPE_STRING; b[6].buffer = (void *)pub;
    b[6].buffer_length = pub_len; b[6].length = &pub_len;
    b[7].buffer_type = MYSQL_TYPE_STRING; b[7].buffer = (void *)phash;
    b[7].buffer_length = phash_len; b[7].length = &phash_len;
    b[8].buffer_type = MYSQL_TYPE_STRING; b[8].buffer = (void *)backend;
    b[8].buffer_length = backend_len; b[8].length = &backend_len;
    mysql_stmt_bind_param(stmt, b);
    mysql_stmt_execute(stmt);
    mysql_stmt_close(stmt);
    db_pool_release(conn);
}

/* -- read-only group info -------------------------------------------------- */

/* Trả thông tin nhóm (tên, mô tả, danh sách thành viên + vai trò) cho UI hiển thị. */
static void handle_get_group_info(int idx, const char *buf)
{
    int my_uid   = clients_get_uid(idx);
    int group_id = 0;
    jget_int(buf, "group_id", &group_id);
    if (group_id <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid group_id\"}");
        return;
    }
    long long cid = (long long)group_id;

    if (!conv_is_member(cid, my_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}");
        return;
    }

    /* Allocate a generous buffer: 4KB metadata + up to 200 members * 128 bytes */
    size_t out_sz = 4096 + 200 * 128;
    char  *out    = (char *)malloc(out_sz);
    if (!out) return;

    if (!conv_get_group_info_json(cid, out, out_sz)) {
        free(out);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Group not found\"}");
        return;
    }
    clients_send(idx, out);
    free(out);
}

/* ── MLS prepare/apply/handshake ────────────────────────────────────────── */

/*
 * Bước 1/2 (prepare): kiểm POLICY của một thay đổi nhóm TRƯỚC khi đụng MLS.
 *
 * Xác thực người gọi có quyền (vd chỉ admin mới add/remove/đổi vai trò), kiểm
 * tham số hợp lệ, rồi cấp một operation_id để client dùng ở bước apply. Chưa
 * mutate gì — chỉ "đặt chỗ" thao tác hợp lệ.
 */
static void handle_prepare_group_change(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid JSON\"}");
        return;
    }
    const char *operation = json_str_obj(root, "operation");
    if (!operation[0]) operation = json_str_obj(root, "group_operation");
    if (!operation[0]) {
        cJSON_Delete(root);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Missing group operation\"}");
        return;
    }
    char operation_name[40] = {0};
    strncpy(operation_name, operation, sizeof(operation_name) - 1);
    operation = operation_name;

    long long cid = 0;
    int target_uid = json_int_obj(root, "user_id", 0);
    if (target_uid <= 0) target_uid = json_int_obj(root, "target_user_id", 0);
    const char *role = json_str_obj(root, "role");

    if (strcmp(operation, "create_group") == 0) {
        char name[200] = {0};
        jget(buf, "name", name, sizeof(name));
        if (!name[0]) strncpy(name, "Unnamed Group", sizeof(name) - 1);
        if (strlen(name) > 99 || !domain_validate_group_name(name)) {
            cJSON_Delete(root);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid group name\"}");
            return;
        }
        int members[50] = {0};
        int count = jget_array(buf, "members", members, 50);
        if (count <= 0) {
            cJSON_Delete(root);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"No members specified\"}");
            return;
        }
        for (int i = 0; i < count; i++) {
            if (!friendship_exists_accepted(my_uid, members[i])) {
                cJSON_Delete(root);
                clients_send(idx,
                    "{\"type\":\"error\",\"msg\":\"Can only add friends to a group\"}");
                return;
            }
        }
        cid = conv_create_group(name, my_uid);
        if (cid < 0) {
            cJSON_Delete(root);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to create group\"}");
            return;
        }
    } else {
        int group_id = json_int_obj(root, "group_id", 0);
        if (group_id <= 0) group_id = json_int_obj(root, "conversation_id", 0);
        if (group_id <= 0) {
            cJSON_Delete(root);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid group_id\"}");
            return;
        }
        cid = (long long)group_id;
        if (!conv_is_member(cid, my_uid)) {
            cJSON_Delete(root);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member of this group\"}");
            return;
        }
        if (conv_is_disbanded(cid)) {
            cJSON_Delete(root);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Group has been disbanded\"}");
            return;
        }
        if (strcmp(operation, "add_member") == 0) {
            if (target_uid <= 0 || !friendship_exists_accepted(my_uid, target_uid)) {
                cJSON_Delete(root);
                clients_send(idx,
                    "{\"type\":\"error\",\"msg\":\"Can only add friends to a group\"}");
                return;
            }
            if (!conv_is_admin(cid, my_uid)) {
                cJSON_Delete(root);
                clients_send(idx, "{\"type\":\"error\",\"msg\":\"Only admins can add members\"}");
                return;
            }
        } else if (strcmp(operation, "leave_group") == 0) {
            if (target_uid <= 0) target_uid = my_uid;
            if (target_uid != my_uid || !conv_is_member(cid, my_uid)) {
                cJSON_Delete(root);
                clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid leave group operation\"}");
                return;
            }
        } else if (strcmp(operation, "remove_member") == 0) {
            if (!conv_is_admin(cid, my_uid) || target_uid <= 0 ||
                !conv_is_member(cid, target_uid) || conv_is_admin(cid, target_uid)) {
                cJSON_Delete(root);
                clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid remove member operation\"}");
                return;
            }
        } else if (strcmp(operation, "set_member_role") == 0) {
            if (!conv_is_admin(cid, my_uid) || target_uid <= 0 ||
                !conv_is_member(cid, target_uid) || !domain_validate_role(role)) {
                cJSON_Delete(root);
                clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid role operation\"}");
                return;
            }
        } else if (strcmp(operation, "update_group_info") == 0) {
            if (!conv_is_admin(cid, my_uid)) {
                cJSON_Delete(root);
                clients_send(idx, "{\"type\":\"error\",\"msg\":\"Only admins can update group info\"}");
                return;
            }
        } else {
            cJSON_Delete(root);
            clients_send(idx, "{\"type\":\"error\",\"msg\":\"Unsupported group operation\"}");
            return;
        }
    }

    char operation_id[65] = {0};
    make_operation_id(operation_id);
    if (!store_pending_op(operation_id, cid, my_uid, operation, target_uid,
                          role, buf)) {
        cJSON_Delete(root);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to prepare group change\"}");
        return;
    }
    cJSON_Delete(root);
    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"type\":\"group_change_prepared\",\"operation_id\":\"%s\","
             "\"conversation_id\":%lld,\"operation\":\"%s\","
             "\"target_user_id\":%d}",
             operation_id, cid, operation, target_uid);
    clients_send(idx, resp);
}

static int fetch_pending_op(const char *operation_id, int actor_id,
                            long long *cid_out, char *operation, int operation_len,
                            int *target_uid_out, char *role, int role_len,
                            char **details_json_out)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    char q[512];
    snprintf(q, sizeof(q),
             "SELECT conversation_id,operation,COALESCE(target_user_id,0),"
             " COALESCE(role,''),COALESCE(details_json,'')"
             " FROM mls_pending_group_ops"
             " WHERE operation_id='%s' AND actor_id=%d"
             "   AND status='prepared' AND expires_at > NOW(3)"
             " LIMIT 1",
             operation_id, actor_id);
    if (mysql_query(conn, q)) { db_pool_release(conn); return 0; }
    MYSQL_RES *res = mysql_store_result(conn);
    db_pool_release(conn);
    if (!res) return 0;
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return 0; }
    if (cid_out) *cid_out = row[0] ? atoll(row[0]) : 0;
    if (operation && operation_len > 0) {
        strncpy(operation, row[1] ? row[1] : "", (size_t)operation_len - 1);
        operation[operation_len - 1] = '\0';
    }
    if (target_uid_out) *target_uid_out = row[2] ? atoi(row[2]) : 0;
    if (role && role_len > 0) {
        strncpy(role, row[3] ? row[3] : "", (size_t)role_len - 1);
        role[role_len - 1] = '\0';
    }
    if (details_json_out) *details_json_out = strdup(row[4] ? row[4] : "");
    mysql_free_result(res);
    return 1;
}

static void mark_pending_applied(const char *operation_id)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    char q[256];
    snprintf(q, sizeof(q),
             "UPDATE mls_pending_group_ops SET status='applied'"
             " WHERE operation_id='%s'",
             operation_id);
    mysql_query(conn, q);
    db_pool_release(conn);
}

static char *fetch_mls_public_state(long long cid)
{
    MYSQL *conn = db_pool_acquire();
    if (!conn) return NULL;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT public_state_b64 FROM mls_group_state"
             " WHERE conversation_id=%lld"
             "   AND ciphersuite='%s'"
             "   AND public_state_b64 IS NOT NULL"
             "   AND public_state_b64!=''"
             " LIMIT 1",
             cid, SECCHAT_MLS_PQ_CIPHERSUITE);
    if (mysql_query(conn, q)) {
        db_pool_release(conn);
        return NULL;
    }
    MYSQL_RES *res = mysql_store_result(conn);
    db_pool_release(conn);
    if (!res) return NULL;
    MYSQL_ROW row = mysql_fetch_row(res);
    unsigned long *lengths = mysql_fetch_lengths(res);
    char *out = NULL;
    if (row && row[0] && lengths) {
        out = (char *)malloc(lengths[0] + 1);
        if (out) {
            memcpy(out, row[0], lengths[0]);
            out[lengths[0]] = '\0';
        }
    }
    mysql_free_result(res);
    return out;
}

static void set_err(char *err, size_t err_sz, const char *msg)
{
    if (!err || err_sz == 0) return;
    snprintf(err, err_sz, "%s", msg ? msg : "unknown error");
}

static void add_unique_member_id(cJSON *arr, int uid)
{
    if (!cJSON_IsArray(arr) || uid <= 0) return;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (cJSON_IsNumber(item) && item->valueint == uid)
            return;
    }
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(uid));
}

static cJSON *expected_members_for_operation(const char *operation, long long cid,
                                             int actor_id, int target_uid,
                                             const char *details_json)
{
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return NULL;
    if (strcmp(operation, "create_group") == 0) {
        add_unique_member_id(arr, actor_id);
        cJSON *details = cJSON_Parse(details_json ? details_json : "{}");
        cJSON *members = details
                       ? cJSON_GetObjectItemCaseSensitive(details, "members")
                       : NULL;
        if (cJSON_IsArray(members)) {
            cJSON *m = NULL;
            cJSON_ArrayForEach(m, members) {
                if (cJSON_IsNumber(m))
                    add_unique_member_id(arr, m->valueint);
            }
        }
        if (details) cJSON_Delete(details);
        return arr;
    }

    int members[512] = {0};
    int count = conv_get_members(cid, members, 512);
    for (int i = 0; i < count; i++) {
        int uid = members[i];
        if ((strcmp(operation, "remove_member") == 0 ||
             strcmp(operation, "leave_group") == 0) && uid == target_uid) {
            continue;
        }
        add_unique_member_id(arr, uid);
    }
    if (strcmp(operation, "add_member") == 0)
        add_unique_member_id(arr, target_uid);
    return arr;
}

static cJSON *run_mls_validator(cJSON *request, char *err, size_t err_sz)
{
    char *json = cJSON_PrintUnformatted(request);
    if (!json) {
        set_err(err, err_sz, "could not serialize MLS validation request");
        return NULL;
    }

    char path[] = "/tmp/secchat_mls_validate_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        free(json);
        set_err(err, err_sz, "could not create MLS validation temp file");
        return NULL;
    }
    size_t len = strlen(json);
    size_t off = 0;
    int write_ok = 1;
    while (off < len) {
        ssize_t n = write(fd, json + off, len - off);
        if (n <= 0) {
            write_ok = 0;
            break;
        }
        off += (size_t)n;
    }
    close(fd);
    free(json);
    if (!write_ok) {
        unlink(path);
        set_err(err, err_sz, "could not write MLS validation request");
        return NULL;
    }

    const char *bin = getenv("SECCHAT_MLS_VALIDATOR_BIN");
    if (!bin || !bin[0])
        bin = "/usr/local/bin/secchat_mls_bridge";
    if (access(bin, X_OK) != 0)
        bin = "secchat_mls_bridge";

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s validate_file %s 2>&1", bin, path);
    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        unlink(path);
        set_err(err, err_sz, "could not execute MLS validator");
        return NULL;
    }

    size_t cap = 8192, pos = 0;
    char *out = (char *)malloc(cap);
    if (!out) {
        pclose(pipe);
        unlink(path);
        set_err(err, err_sz, "out of memory reading MLS validator output");
        return NULL;
    }
    out[0] = '\0';
    char chunk[2048];
    while (fgets(chunk, sizeof(chunk), pipe)) {
        size_t chunk_len = strlen(chunk);
        if (pos + chunk_len + 1 > 4 * 1024 * 1024) {
            free(out);
            pclose(pipe);
            unlink(path);
            set_err(err, err_sz, "MLS validator output too large");
            return NULL;
        }
        if (pos + chunk_len + 1 > cap) {
            while (pos + chunk_len + 1 > cap) cap *= 2;
            char *tmp = (char *)realloc(out, cap);
            if (!tmp) {
                free(out);
                pclose(pipe);
                unlink(path);
                set_err(err, err_sz, "out of memory expanding MLS validator output");
                return NULL;
            }
            out = tmp;
        }
        memcpy(out + pos, chunk, chunk_len);
        pos += chunk_len;
        out[pos] = '\0';
    }
    int status = pclose(pipe);
    unlink(path);

    cJSON *resp = cJSON_Parse(out);
    if (!resp) {
        set_err(err, err_sz, out[0] ? out : "MLS validator returned no JSON");
        free(out);
        return NULL;
    }
    free(out);
    cJSON *ok = cJSON_GetObjectItemCaseSensitive(resp, "ok");
    if (!cJSON_IsTrue(ok)) {
        const char *msg = json_str_obj(resp, "error");
        set_err(err, err_sz, msg[0] ? msg : "MLS validator rejected request");
        cJSON_Delete(resp);
        return NULL;
    }
    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        set_err(err, err_sz, "MLS validator exited unsuccessfully");
        cJSON_Delete(resp);
        return NULL;
    }
    return resp;
}

static cJSON *validate_mls_membership_change(const char *operation, long long cid,
                                             int actor_id, int target_uid,
                                             const char *details_json,
                                             const char *commit_b64,
                                             const char *group_info_b64,
                                             const char *ratchet_tree_b64,
                                             char *err, size_t err_sz)
{
    if (!operation || !operation[0] || !group_info_b64 || !group_info_b64[0] ||
        !ratchet_tree_b64 || !ratchet_tree_b64[0]) {
        set_err(err, err_sz, "MLS GroupInfo and RatchetTree are required");
        return NULL;
    }
    if (strcmp(operation, "create_group") != 0 &&
        (!commit_b64 || !commit_b64[0])) {
        set_err(err, err_sz, "MLS commit is required");
        return NULL;
    }

    cJSON *req = cJSON_CreateObject();
    if (!req) {
        set_err(err, err_sz, "could not allocate MLS validation request");
        return NULL;
    }
    cJSON_AddStringToObject(req, "cmd",
        strcmp(operation, "create_group") == 0
            ? "validate_group_create" : "validate_group_commit");
    cJSON_AddNumberToObject(req, "conversation_id", (double)cid);
    cJSON_AddNumberToObject(req, "actor_user_id", actor_id);
    cJSON_AddStringToObject(req, "group_info_b64", group_info_b64);
    cJSON_AddStringToObject(req, "ratchet_tree_b64", ratchet_tree_b64);
    if (commit_b64 && commit_b64[0])
        cJSON_AddStringToObject(req, "commit_b64", commit_b64);

    char *public_state = NULL;
    if (strcmp(operation, "create_group") != 0) {
        public_state = fetch_mls_public_state(cid);
        if (!public_state) {
            cJSON_Delete(req);
            set_err(err, err_sz, "missing prior validated MLS public state");
            return NULL;
        }
        cJSON_AddStringToObject(req, "public_state_b64", public_state);
    }

    cJSON *expected = expected_members_for_operation(
        operation, cid, actor_id, target_uid, details_json);
    if (!expected) {
        free(public_state);
        cJSON_Delete(req);
        set_err(err, err_sz, "could not build expected MLS member set");
        return NULL;
    }
    cJSON_AddItemToObject(req, "expected_member_ids", expected);

    cJSON *resp = run_mls_validator(req, err, err_sz);
    free(public_state);
    cJSON_Delete(req);
    if (!resp)
        return NULL;
    const char *cs = json_str_obj(resp, "ciphersuite");
    if (strcmp(cs, SECCHAT_MLS_PQ_CIPHERSUITE) != 0) {
        set_err(err, err_sz, "MLS validator returned non-X-Wing ciphersuite");
        cJSON_Delete(resp);
        return NULL;
    }
    return resp;
}

static void store_welcomes_from_json(cJSON *root, long long cid, int sender_id,
                                     long long epoch, const char *operation_id)
{
    cJSON *welcomes = cJSON_GetObjectItemCaseSensitive(root, "welcomes");
    if (cJSON_IsArray(welcomes)) {
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, welcomes) {
            int target = json_int_obj(item, "user_id", 0);
            if (target <= 0) target = json_int_obj(item, "target_user_id", 0);
            const char *welcome = json_str_obj(item, "welcome_b64");
            if (target > 0 && welcome[0])
                store_mls_handshake(cid, sender_id, target, "welcome",
                                    epoch, operation_id, welcome);
        }
        return;
    }
    int target = json_int_obj(root, "target_user_id", 0);
    const char *welcome = json_str_obj(root, "welcome_b64");
    if (target > 0 && welcome[0])
        store_mls_handshake(cid, sender_id, target, "welcome",
                            epoch, operation_id, welcome);
}

static void notify_added_to_group(long long cid, int uid, int by_uid,
                                  const char *name,
                                  const char *member_ids_json,
                                  const char *members_json,
                                  const char *operation_id,
                                  GroupSystemEventMeta system_event)
{
    char esc_actor[USERNAME_LEN * 2 + 8] = {0};
    escaped_username_for_uid(by_uid, esc_actor, sizeof(esc_actor));
    char esc_name[210] = {0};
    json_esc(name ? name : "", esc_name, sizeof(esc_name));
    size_t notif_sz = strlen(esc_name) + strlen(esc_actor)
                    + strlen(member_ids_json) + strlen(members_json) + 512;
    char *notif = (char *)malloc(notif_sz);
    if (!notif) return;
    snprintf(notif, notif_sz,
             "{\"type\":\"added_to_group\",\"conversation_id\":%lld,"
             "\"name\":\"%s\",\"by\":\"%s\",\"by_username\":\"%s\","
             "\"by_user_id\":%d,\"operation_id\":\"%s\","
             "\"system_event_id\":%lld,\"after_message_id\":%lld,"
             "\"event_time\":\"%s\","
             "\"member_ids\":%s,\"members\":%s}",
             cid, esc_name, esc_actor, esc_actor, by_uid,
             operation_id ? operation_id : "",
             system_event.id, system_event.after_message_id,
             system_event.event_time,
             member_ids_json, members_json);
    clients_send_to_uid(uid, notif);
    if (!clients_is_online(uid))
        notif_enqueue(uid, "group", notif);
    free(notif);
}

/*
 * Bước 2/2 (apply): client gửi kèm các artifact MLS (Commit/Welcome/GroupInfo/
 * RatchetTree). Server gọi MLS validator trên PUBLIC group state để chắc chắn
 * artifact hợp lệ và đúng tập thành viên kỳ vọng; CHỈ KHI validate pass mới
 * mutate bảng membership + lưu handshake cho thành viên replay. Validate fail
 * thì không lưu gì, membership giữ nguyên.
 */
static void handle_apply_group_change(int idx, const char *buf)
{
    uint64_t t0 = metrics_now_us();
    int my_uid = clients_get_uid(idx);
    char operation_id[80] = {0};
    jget(buf, "operation_id", operation_id, sizeof(operation_id));
    if (!operation_id[0]) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Missing operation_id\"}");
        return;
    }
    long long cid = 0;
    int target_uid = 0;
    char operation[40] = {0};
    char role[20] = {0};
    char *details = NULL;
    if (!fetch_pending_op(operation_id, my_uid, &cid, operation, sizeof(operation),
                          &target_uid, role, sizeof(role), &details)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Pending group operation not found\"}");
        return;
    }

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        free(details);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid JSON\"}");
        return;
    }
    long long epoch = (long long)json_int_obj(root, "epoch", 0);
    const char *commit_b64 = json_str_obj(root, "commit_b64");
    const char *group_info_b64 = json_str_obj(root, "group_info_b64");
    const char *group_id_b64 = json_str_obj(root, "group_id_b64");
    const char *ratchet_tree_b64 = json_str_obj(root, "ratchet_tree_b64");
    const char *control_b64 = json_str_obj(root, "control_b64");
    int membership_change = (
        strcmp(operation, "create_group") == 0 ||
        strcmp(operation, "add_member") == 0 ||
        strcmp(operation, "remove_member") == 0 ||
        strcmp(operation, "leave_group") == 0);
    if (membership_change &&
        (!commit_b64[0] || !group_info_b64[0] ||
         !group_id_b64[0] || !ratchet_tree_b64[0])) {
        cJSON_Delete(root);
        free(details);
        clients_send(idx,
            "{\"type\":\"error\",\"msg\":\"MLS commit, GroupInfo, group_id and RatchetTree are required\"}");
        return;
    }
    if ((strcmp(operation, "set_member_role") == 0 ||
         strcmp(operation, "update_group_info") == 0) && !control_b64[0]) {
        cJSON_Delete(root);
        free(details);
        clients_send(idx,
            "{\"type\":\"error\",\"msg\":\"Encrypted MLS control message is required\"}");
        return;
    }

    cJSON *mls_validation = NULL;
    if (membership_change) {
        char validation_error[1024] = {0};
        mls_validation = validate_mls_membership_change(
            operation, cid, my_uid, target_uid, details,
            commit_b64, group_info_b64, ratchet_tree_b64,
            validation_error, sizeof(validation_error));
        if (!mls_validation) {
            char esc[2048] = {0};
            json_esc(validation_error[0] ? validation_error : "commit rejected",
                     esc, sizeof(esc));
            char resp[2300];
            snprintf(resp, sizeof(resp),
                     "{\"type\":\"error\",\"msg\":\"MLS validation failed: %s\"}",
                     esc);
            cJSON_Delete(root);
            free(details);
            clients_send(idx, resp);
            return;
        }
        cJSON *validated_epoch = cJSON_GetObjectItemCaseSensitive(mls_validation, "epoch");
        if (cJSON_IsNumber(validated_epoch)) {
            long long expected_epoch = (long long)validated_epoch->valuedouble;
            if (epoch != expected_epoch) {
                cJSON_Delete(mls_validation);
                cJSON_Delete(root);
                free(details);
                clients_send(idx,
                    "{\"type\":\"error\",\"msg\":\"MLS validation failed: epoch mismatch\"}");
                return;
            }
        }
    }

    if (commit_b64[0])
        store_mls_handshake(cid, my_uid, 0, "commit", epoch, operation_id, commit_b64);
    if (group_info_b64[0])
        store_mls_handshake(cid, my_uid, 0, "group_info", epoch, operation_id, group_info_b64);
    if (control_b64[0])
        store_mls_handshake(cid, my_uid, 0, "control", epoch, operation_id, control_b64);
    store_welcomes_from_json(root, cid, my_uid, epoch, operation_id);
    if (mls_validation) {
        const char *validated_cs = json_str_obj(mls_validation, "ciphersuite");
        const char *public_state_b64 = json_str_obj(mls_validation, "public_state_b64");
        const char *public_state_hash = json_str_obj(mls_validation, "public_state_hash");
        const char *backend = json_str_obj(mls_validation, "backend");
        upsert_mls_group_state(cid, group_id_b64, epoch, operation_id, group_info_b64,
                               validated_cs, public_state_b64,
                               public_state_hash, backend);
    }

    if (strcmp(operation, "create_group") == 0) {
        cJSON *details_root = cJSON_Parse(details ? details : "{}");
        char name[200] = {0};
        conv_add_member(cid, my_uid);
        conv_role_set(cid, my_uid, "admin");
        if (details_root) {
            const char *n = json_str_obj(details_root, "name");
            strncpy(name, n[0] ? n : "Unnamed Group", sizeof(name) - 1);
            cJSON *arr = cJSON_GetObjectItemCaseSensitive(details_root, "members");
            if (cJSON_IsArray(arr)) {
                cJSON *m = NULL;
                cJSON_ArrayForEach(m, arr) {
                    if (!cJSON_IsNumber(m)) continue;
                    int uid = m->valueint;
                    if (uid <= 0) continue;
                    conv_add_member(cid, uid);
                    conv_role_set(cid, uid, "member");
                }
            }
            cJSON_Delete(details_root);
        }
        char member_ids_json[2048] = {0};
        char members_json[4096] = {0};
        conv_get_member_ids_json(cid, member_ids_json, sizeof(member_ids_json));
        conv_get_members_roles_json(cid, members_json, sizeof(members_json));
        char esc_name[420];
        json_esc(name[0] ? name : "Unnamed Group", esc_name, sizeof(esc_name));
        char resp[8192];
        snprintf(resp, sizeof(resp),
                 "{\"type\":\"group_created\",\"conversation_id\":%lld,"
                 "\"name\":\"%s\",\"operation_id\":\"%s\","
                 "\"mls_validated\":true,\"ciphersuite\":\"%s\","
                 "\"member_ids\":%s,\"members\":%s}",
                 cid, esc_name, operation_id, SECCHAT_MLS_PQ_CIPHERSUITE,
                 member_ids_json, members_json);
        clients_send(idx, resp);
        int members[200];
        int nm = conv_get_members(cid, members, 200);
        for (int i = 0; i < nm; i++)
            if (members[i] != my_uid) {
                GroupSystemEventMeta ev = store_group_system_event(
                    cid, "member_added", my_uid, members[i], "",
                    operation_id, members_json);
                notify_added_to_group(cid, members[i], my_uid,
                                      name[0] ? name : "Unnamed Group",
                                      member_ids_json, members_json,
                                      operation_id, ev);
            }
        metrics_group_created();
    } else if (strcmp(operation, "add_member") == 0) {
        conv_add_member(cid, target_uid);
        conv_role_set(cid, target_uid, "member");
        char member_ids_json[2048] = {0};
        char members_json[4096] = {0};
        conv_get_member_ids_json(cid, member_ids_json, sizeof(member_ids_json));
        conv_get_members_roles_json(cid, members_json, sizeof(members_json));
        char esc_target[USERNAME_LEN * 2 + 8] = {0};
        char esc_actor[USERNAME_LEN * 2 + 8] = {0};
        escaped_username_for_uid(target_uid, esc_target, sizeof(esc_target));
        escaped_username_for_uid(my_uid, esc_actor, sizeof(esc_actor));
        GroupSystemEventMeta ev = store_group_system_event(
            cid, "member_added", my_uid, target_uid, "",
            operation_id, members_json);
        char notif[8192];
        snprintf(notif, sizeof(notif),
                 "{\"type\":\"member_added\",\"group_id\":%lld,"
                 "\"user_id\":%d,\"username\":\"%s\","
                 "\"by_user_id\":%d,\"by_username\":\"%s\","
                 "\"operation\":\"add_member\","
                 "\"operation_id\":\"%s\","
                 "\"system_event_id\":%lld,\"after_message_id\":%lld,"
                 "\"event_time\":\"%s\","
                 "\"member_ids\":%s,\"members\":%s}",
                 cid, target_uid, esc_target, my_uid, esc_actor, operation_id,
                 ev.id, ev.after_message_id, ev.event_time,
                 member_ids_json, members_json);
        clients_broadcast_conv(cid, notif);
        notify_added_to_group(cid, target_uid, my_uid, "",
                              member_ids_json, members_json, operation_id, ev);
    } else if (strcmp(operation, "remove_member") == 0
               || strcmp(operation, "leave_group") == 0) {
        conv_role_delete(cid, target_uid);
        conv_remove_member(cid, target_uid);
        char member_ids_json[2048] = {0};
        char members_json[4096] = {0};
        conv_get_member_ids_json(cid, member_ids_json, sizeof(member_ids_json));
        conv_get_members_roles_json(cid, members_json, sizeof(members_json));
        char esc_target[USERNAME_LEN * 2 + 8] = {0};
        char esc_actor[USERNAME_LEN * 2 + 8] = {0};
        escaped_username_for_uid(target_uid, esc_target, sizeof(esc_target));
        escaped_username_for_uid(my_uid, esc_actor, sizeof(esc_actor));
        GroupSystemEventMeta ev = store_group_system_event(
            cid,
            strcmp(operation, "leave_group") == 0 ? "member_left" : "member_removed",
            my_uid, target_uid, "", operation_id, members_json);
        char notif[8192];
        snprintf(notif, sizeof(notif),
                 "{\"type\":\"member_removed\",\"group_id\":%lld,"
                 "\"user_id\":%d,\"username\":\"%s\","
                 "\"by_user_id\":%d,\"by_username\":\"%s\","
                 "\"operation\":\"%s\","
                 "\"operation_id\":\"%s\","
                 "\"system_event_id\":%lld,\"after_message_id\":%lld,"
                 "\"event_time\":\"%s\","
                 "\"member_ids\":%s,\"members\":%s}",
                 cid, target_uid, esc_target, my_uid, esc_actor,
                 operation, operation_id,
                 ev.id, ev.after_message_id, ev.event_time,
                 member_ids_json, members_json);
        clients_send_to_uid(target_uid, notif);
        if (!clients_is_online(target_uid))
            notif_enqueue(target_uid, "group", notif);
        clients_broadcast_conv(cid, notif);
    } else if (strcmp(operation, "set_member_role") == 0) {
        conv_role_set(cid, target_uid, role);
        char member_ids_json[2048] = {0};
        char members_json[4096] = {0};
        conv_get_member_ids_json(cid, member_ids_json, sizeof(member_ids_json));
        conv_get_members_roles_json(cid, members_json, sizeof(members_json));
        char esc_target[USERNAME_LEN * 2 + 8] = {0};
        char esc_actor[USERNAME_LEN * 2 + 8] = {0};
        escaped_username_for_uid(target_uid, esc_target, sizeof(esc_target));
        escaped_username_for_uid(my_uid, esc_actor, sizeof(esc_actor));
        GroupSystemEventMeta ev = store_group_system_event(
            cid, "member_role_changed", my_uid, target_uid, role,
            operation_id, members_json);
        char notif[8192];
        snprintf(notif, sizeof(notif),
                 "{\"type\":\"member_role_changed\",\"group_id\":%lld,"
                 "\"user_id\":%d,\"username\":\"%s\","
                 "\"role\":\"%s\",\"by_user_id\":%d,\"by_username\":\"%s\","
                 "\"operation\":\"set_member_role\","
                 "\"operation_id\":\"%s\","
                 "\"system_event_id\":%lld,\"after_message_id\":%lld,"
                 "\"event_time\":\"%s\","
                 "\"member_ids\":%s,\"members\":%s}",
                 cid, target_uid, esc_target, role, my_uid, esc_actor,
                 operation_id,
                 ev.id, ev.after_message_id, ev.event_time,
                 member_ids_json, members_json);
        clients_broadcast_conv(cid, notif);
    } else if (strcmp(operation, "update_group_info") == 0) {
        cJSON *details_root = cJSON_Parse(details ? details : "{}");
        const char *name = details_root ? json_str_obj(details_root, "name") : "";
        const char *description = details_root ? json_str_obj(details_root, "description") : "";
        conv_update_info(cid, name[0] ? name : NULL,
                         description[0] ? description : NULL,
                         NULL, 0, NULL);
        if (details_root) cJSON_Delete(details_root);
        char notif[8192];
        char esc_name[210] = {0};
        char esc_actor[USERNAME_LEN * 2 + 8] = {0};
        json_esc(name, esc_name, sizeof(esc_name));
        escaped_username_for_uid(my_uid, esc_actor, sizeof(esc_actor));
        char members_json[4096] = {0};
        conv_get_members_roles_json(cid, members_json, sizeof(members_json));
        GroupSystemEventMeta ev = store_group_system_event(
            cid, "group_info_updated", my_uid, 0, "",
            operation_id, members_json);
        snprintf(notif, sizeof(notif),
                 "{\"type\":\"group_info_updated\",\"group_id\":%lld,"
                 "\"name\":\"%s\",\"has_new_avatar\":false,"
                 "\"by_user_id\":%d,\"by_username\":\"%s\","
                 "\"operation\":\"update_group_info\",\"operation_id\":\"%s\","
                 "\"system_event_id\":%lld,\"after_message_id\":%lld,"
                 "\"event_time\":\"%s\",\"members\":%s}",
                 cid, esc_name, my_uid, esc_actor, operation_id,
                 ev.id, ev.after_message_id, ev.event_time, members_json);
        clients_broadcast_conv(cid, notif);
    }
    mark_pending_applied(operation_id);
    if (mls_validation) cJSON_Delete(mls_validation);
    cJSON_Delete(root);
    free(details);
    metrics_lat_group_us(metrics_now_us() - t0);
    char ok[320];
    snprintf(ok, sizeof(ok),
             "{\"type\":\"group_change_applied\",\"operation_id\":\"%s\","
             "\"conversation_id\":%lld,\"mls_validated\":%s,"
             "\"ciphersuite\":\"%s\"}",
             operation_id, cid, membership_change ? "true" : "false",
             membership_change ? SECCHAT_MLS_PQ_CIPHERSUITE : "");
    clients_send(idx, ok);
}

/* Trả các artifact MLS (Welcome/Commit) đã lưu theo thứ tự để thành viên replay
 * đúng và bắt kịp epoch hiện hành khi online lại hoặc tải lại history. */
static void handle_get_mls_handshake(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);
    int group_id = 0;
    jget_int(buf, "group_id", &group_id);
    if (group_id <= 0) jget_int(buf, "conversation_id", &group_id);
    if (group_id <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid group_id\"}");
        return;
    }
    long long cid = (long long)group_id;
    if (!conv_is_member(cid, my_uid)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Not a member\"}");
        return;
    }
    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    char q[512];
    snprintf(q, sizeof(q),
             "SELECT id,sender_id,COALESCE(target_user_id,0),kind,epoch,"
             " COALESCE(operation_id,''),mls_message_b64"
             " FROM mls_group_handshake"
             " WHERE conversation_id=%lld"
             "   AND (target_user_id IS NULL OR target_user_id=%d OR sender_id=%d)"
             " ORDER BY id ASC LIMIT 500",
             cid, my_uid, my_uid);
    if (mysql_query(conn, q)) { db_pool_release(conn); return; }
    MYSQL_RES *res = mysql_store_result(conn);
    db_pool_release(conn);
    if (!res) return;
    size_t cap = 65536;
    char *out = (char *)malloc(cap);
    if (!out) { mysql_free_result(res); return; }
    size_t pos = (size_t)snprintf(out, cap,
        "{\"type\":\"mls_handshake\",\"conversation_id\":%lld,\"items\":[", cid);
    MYSQL_ROW row;
    int first = 1;
    while ((row = mysql_fetch_row(res))) {
        const char *msg = row[6] ? row[6] : "";
        size_t need = strlen(msg) * 2 + 512;
        if (pos + need >= cap) break;
        char *esc_msg = (char *)malloc(strlen(msg) * 2 + 8);
        if (!esc_msg) continue;
        json_esc(msg, esc_msg, (int)(strlen(msg) * 2 + 8));
        pos += (size_t)snprintf(out + pos, cap - pos,
            "%s{\"id\":%s,\"sender_id\":%s,\"target_user_id\":%s,"
            "\"kind\":\"%s\",\"epoch\":%s,\"operation_id\":\"%s\","
            "\"mls_message_b64\":\"%s\"}",
            first ? "" : ",",
            row[0] ? row[0] : "0",
            row[1] ? row[1] : "0",
            row[2] ? row[2] : "0",
            row[3] ? row[3] : "",
            row[4] ? row[4] : "0",
            row[5] ? row[5] : "",
            esc_msg);
        first = 0;
        free(esc_msg);
    }
    snprintf(out + pos, cap - pos, "]}");
    mysql_free_result(res);
    clients_send(idx, out);
    free(out);
}

/* ── dispatcher ──────────────────────────────────────────────────────────── */

int groups_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "prepare_group_change") == 0) {
        handle_prepare_group_change(idx, buf);
        return 1;
    }
    if (strcmp(type, "apply_group_change") == 0) {
        handle_apply_group_change(idx, buf);
        return 1;
    }
    if (strcmp(type, "get_mls_handshake") == 0) {
        handle_get_mls_handshake(idx, buf);
        return 1;
    }
    if (strcmp(type, "get_group_info") == 0) {
        handle_get_group_info(idx, buf);
        return 1;
    }
    return 0;
}
