/*
 * repository/user_repo.c — truy cập bảng `users` (tài khoản, hash mật khẩu,
 * trạng thái online, thông tin hồ sơ) bằng prepared statement.
 */
#include "user_repo.h"

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

static int mysql_connection_lost_code(int err)
{
    return err == CR_SERVER_GONE_ERROR || err == CR_SERVER_LOST;
}

static int stmt_error_code(MYSQL_STMT *s)
{
    unsigned int err = s ? mysql_stmt_errno(s) : 0;
    return err ? (int)err : 1;
}

/* ── internal helpers ─────────────────────────────────────────────────────── */

/* Execute a prepared write statement.  Returns 0 on success, non-zero on error. */
static int stmt_run_c(MYSQL *c, const char *sql, MYSQL_BIND *b, unsigned int n)
{
    MYSQL_STMT *s = mysql_stmt_init(c);
    if (!s) return 1;
    if (mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql))) {
        log_warn("user_repo stmt_prepare: %s", mysql_stmt_error(s));
        int err = stmt_error_code(s);
        mysql_stmt_close(s); return err;
    }
    if (n > 0 && mysql_stmt_bind_param(s, b)) {
        log_warn("user_repo stmt_bind: %s", mysql_stmt_error(s));
        int err = stmt_error_code(s);
        mysql_stmt_close(s); return err;
    }
    uint64_t t0 = metrics_now_us();
    int rc = mysql_stmt_execute(s);
    metrics_lat_db_us(metrics_now_us() - t0);
    metrics_db_query(rc == 0);
    if (rc) log_warn("user_repo stmt_execute: %s", mysql_stmt_error(s));
    int err = rc ? stmt_error_code(s) : 0;
    mysql_stmt_close(s);
    return err;
}

/* Escape LIKE metacharacters (%, _, \). */
static void like_esc(char *dst, const char *src, size_t dstsz)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 3 < dstsz; i++) {
        if (src[i] == '%' || src[i] == '_' || src[i] == '\\')
            dst[j++] = '\\';
        dst[j++] = (unsigned char)src[i];
    }
    dst[j] = '\0';
}

/* ── Write operations ─────────────────────────────────────────────────────── */

int user_repo_create(const char *username, const char *email,
                     const char *stored_hash)
{
    const char *sql =
        "INSERT INTO users(username, email, password_hash, display_name)"
        " VALUES(?,?,?,?)";

    MYSQL_BIND b[4];
    memset(b, 0, sizeof(b));

    unsigned long uname_len = (unsigned long)strlen(username);
    unsigned long hash_len  = (unsigned long)strlen(stored_hash);
    unsigned long email_len = (email && email[0]) ? (unsigned long)strlen(email) : 0;

    b[0].buffer_type   = MYSQL_TYPE_STRING;
    b[0].buffer        = (void *)username;
    b[0].buffer_length = uname_len;

    if (email && email[0]) {
        b[1].buffer_type   = MYSQL_TYPE_STRING;
        b[1].buffer        = (void *)email;
        b[1].buffer_length = email_len;
    } else {
        b[1].buffer_type = MYSQL_TYPE_NULL;
    }

    b[2].buffer_type   = MYSQL_TYPE_STRING;
    b[2].buffer        = (void *)stored_hash;
    b[2].buffer_length = hash_len;

    b[3].buffer_type   = MYSQL_TYPE_STRING;  /* display_name = username */
    b[3].buffer        = (void *)username;
    b[3].buffer_length = uname_len;

    for (int attempt = 0; attempt < 2; attempt++) {
        MYSQL *c = db_pool_acquire();
        if (!c) return 0;
        int err = stmt_run_c(c, sql, b, 4);
        db_pool_release(c);
        if (err == 0)
            return 1;
        if (!mysql_connection_lost_code(err))
            return 0;
        log_warn("user_repo_create: retrying after lost MySQL connection");
    }
    return 0;
}

int user_repo_update_profile(int uid,
                              const char *display_name, const char *bio)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    const char *sql =
        "UPDATE users SET display_name=?, bio=? WHERE id=?";
    MYSQL_BIND b[3];
    memset(b, 0, sizeof(b));

    unsigned long dn_len  = (unsigned long)strlen(display_name ? display_name : "");
    unsigned long bio_len = (unsigned long)strlen(bio ? bio : "");

    b[0].buffer_type   = MYSQL_TYPE_STRING;
    b[0].buffer        = (void *)(display_name ? display_name : "");
    b[0].buffer_length = dn_len;

    b[1].buffer_type   = MYSQL_TYPE_STRING;
    b[1].buffer        = (void *)(bio ? bio : "");
    b[1].buffer_length = bio_len;

    b[2].buffer_type = MYSQL_TYPE_LONG;
    b[2].buffer      = &uid;

    int rc = stmt_run_c(c, sql, b, 3) ? 0 : 1;
    db_pool_release(c);
    return rc;
}

int user_repo_set_avatar(int uid,
                          const unsigned char *data, size_t len,
                          const char *mime)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    const char *sql =
        "UPDATE users SET avatar=?, avatar_mime=? WHERE id=?";
    MYSQL_BIND b[3];
    memset(b, 0, sizeof(b));

    unsigned long dlen  = (unsigned long)len;
    unsigned long mlen  = (unsigned long)strlen(mime);

    b[0].buffer_type   = MYSQL_TYPE_BLOB;
    b[0].buffer        = (void *)data;
    b[0].buffer_length = dlen;
    b[0].length        = &dlen;

    b[1].buffer_type   = MYSQL_TYPE_STRING;
    b[1].buffer        = (void *)mime;
    b[1].buffer_length = mlen;

    b[2].buffer_type = MYSQL_TYPE_LONG;
    b[2].buffer      = &uid;

    int rc = stmt_run_c(c, sql, b, 3) ? 0 : 1;
    db_pool_release(c);
    return rc;
}

int user_repo_remove_avatar(int uid)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[128];
    snprintf(q, sizeof(q),
             "UPDATE users SET avatar=NULL, avatar_mime=NULL WHERE id=%d", uid);
    int rc = (mysql_query(c, q) == 0) ? 1 : 0;
    db_pool_release(c);
    return rc;
}

int user_repo_set_status(int uid, const char *status)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    const char *sql = (strcmp(status, "offline") == 0)
        ? "UPDATE users SET status=?, last_seen=NOW() WHERE id=?"
        : "UPDATE users SET status=? WHERE id=?";
    unsigned long slen = (unsigned long)strlen(status);
    MYSQL_BIND b[2]; memset(b, 0, sizeof(b));
    b[0].buffer_type   = MYSQL_TYPE_STRING;
    b[0].buffer        = (void *)status;
    b[0].buffer_length = slen;
    b[1].buffer_type   = MYSQL_TYPE_LONG;
    b[1].buffer        = (void *)&uid;
    int rc = (stmt_run_c(c, sql, b, 2) == 0) ? 1 : 0;
    db_pool_release(c);
    return rc;
}

/* ── Read operations ──────────────────────────────────────────────────────── */

int user_repo_find_for_auth(const char *login,
                             int *out_uid,
                             char *out_username, int uname_len,
                             char *out_hash,     int hash_len)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    /* Email first, then username (backward compat) */
    const char *sql =
        "SELECT id, username, password_hash FROM users"
        " WHERE email=? OR username=?"
        " ORDER BY (email=?) DESC LIMIT 1";

    MYSQL_STMT *s = mysql_stmt_init(c);
    if (!s) { db_pool_release(c); return 0; }

    if (mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql))) {
        mysql_stmt_close(s); db_pool_release(c); return 0;
    }

    unsigned long login_len = (unsigned long)strlen(login);
    MYSQL_BIND in_b[3];
    memset(in_b, 0, sizeof(in_b));
    for (int i = 0; i < 3; i++) {
        in_b[i].buffer_type   = MYSQL_TYPE_STRING;
        in_b[i].buffer        = (void *)login;
        in_b[i].buffer_length = login_len;
    }
    if (mysql_stmt_bind_param(s, in_b)) {
        mysql_stmt_close(s); db_pool_release(c); return 0;
    }

    uint64_t t0 = metrics_now_us();
    int exec_rc = mysql_stmt_execute(s);
    metrics_lat_db_us(metrics_now_us() - t0);
    metrics_db_query(exec_rc == 0);
    if (exec_rc) { mysql_stmt_close(s); db_pool_release(c); return 0; }

    int          uid_col = -1;
    char         un_col[65]  = {0};
    char         pw_col[200] = {0};
    unsigned long un_len = 0, pw_len = 0;

    MYSQL_BIND out_b[3];
    memset(out_b, 0, sizeof(out_b));
    out_b[0].buffer_type   = MYSQL_TYPE_LONG;
    out_b[0].buffer        = &uid_col;
    out_b[1].buffer_type   = MYSQL_TYPE_STRING;
    out_b[1].buffer        = un_col;
    out_b[1].buffer_length = sizeof(un_col) - 1;
    out_b[1].length        = &un_len;
    out_b[2].buffer_type   = MYSQL_TYPE_STRING;
    out_b[2].buffer        = pw_col;
    out_b[2].buffer_length = sizeof(pw_col) - 1;
    out_b[2].length        = &pw_len;

    if (mysql_stmt_bind_result(s, out_b) || mysql_stmt_store_result(s)) {
        mysql_stmt_close(s); db_pool_release(c); return 0;
    }

    int found = 0;
    if (mysql_stmt_fetch(s) == 0 && uid_col > 0) {
        found = 1;
        un_col[un_len < sizeof(un_col) ? un_len : sizeof(un_col)-1] = '\0';
        pw_col[pw_len < sizeof(pw_col) ? pw_len : sizeof(pw_col)-1] = '\0';
        if (out_uid)      *out_uid = uid_col;
        if (out_username) {
            strncpy(out_username, un_col, uname_len - 1);
            out_username[uname_len - 1] = '\0';
        }
        if (out_hash) {
            strncpy(out_hash, pw_col, hash_len - 1);
            out_hash[hash_len - 1] = '\0';
        }
    }
    mysql_stmt_free_result(s);
    mysql_stmt_close(s);
    db_pool_release(c);
    return found;
}

int user_repo_find_by_id(int uid, UserRecord *out)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[256];
    snprintf(q, sizeof(q),
             "SELECT id, username, email, display_name, status,"
             " DATE_FORMAT(last_seen, '%%Y-%%m-%%d %%H:%%i:%%s')"
             " FROM users WHERE id=%d LIMIT 1", uid);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return 0;
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return 0; }

    out->id = atoi(row[0]);
    strncpy(out->username,     row[1] ? row[1] : "", sizeof(out->username) - 1);
    strncpy(out->email,        row[2] ? row[2] : "", sizeof(out->email) - 1);
    strncpy(out->display_name, row[3] ? row[3] : "", sizeof(out->display_name) - 1);
    strncpy(out->status,       row[4] ? row[4] : "offline", sizeof(out->status) - 1);
    strncpy(out->last_seen,    row[5] ? row[5] : "", sizeof(out->last_seen) - 1);
    mysql_free_result(res);
    return 1;
}

int user_repo_search(const char *query, int exclude_uid,
                     UserRecord *out, int max)
{
    if (!query || strlen(query) < 2) return 0;
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char like_q[270];
    like_esc(like_q, query, sizeof(like_q));
    char like_pat[275];
    snprintf(like_pat, sizeof(like_pat), "%%%s%%", like_q);

    const char *sql =
        "SELECT id, username, display_name, status FROM users"
        " WHERE username LIKE ? ESCAPE '\\\\' AND id != ? LIMIT 20";

    MYSQL_STMT *s = mysql_stmt_init(c);
    if (!s) { db_pool_release(c); return 0; }
    if (mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql))) {
        mysql_stmt_close(s); db_pool_release(c); return 0;
    }

    unsigned long pat_len = (unsigned long)strlen(like_pat);
    MYSQL_BIND in_b[2];
    memset(in_b, 0, sizeof(in_b));
    in_b[0].buffer_type   = MYSQL_TYPE_STRING;
    in_b[0].buffer        = like_pat;
    in_b[0].buffer_length = pat_len;
    in_b[1].buffer_type   = MYSQL_TYPE_LONG;
    in_b[1].buffer        = &exclude_uid;

    if (mysql_stmt_bind_param(s, in_b) || mysql_stmt_execute(s) ||
        mysql_stmt_store_result(s)) {
        mysql_stmt_close(s); db_pool_release(c); return 0;
    }

    int          row_id  = 0;
    char         row_un[65]   = {0};
    char         row_dn[101]  = {0};
    char         row_st[16]   = {0};
    unsigned long ulen = 0, dlen = 0, slen = 0;
    char          dn_null = 0;

    MYSQL_BIND out_b[4];
    memset(out_b, 0, sizeof(out_b));
    out_b[0].buffer_type   = MYSQL_TYPE_LONG;
    out_b[0].buffer        = &row_id;
    out_b[1].buffer_type   = MYSQL_TYPE_STRING;
    out_b[1].buffer        = row_un;
    out_b[1].buffer_length = sizeof(row_un) - 1;
    out_b[1].length        = &ulen;
    out_b[2].buffer_type   = MYSQL_TYPE_STRING;
    out_b[2].buffer        = row_dn;
    out_b[2].buffer_length = sizeof(row_dn) - 1;
    out_b[2].length        = &dlen;
    out_b[2].is_null       = (bool *)&dn_null;
    out_b[3].buffer_type   = MYSQL_TYPE_STRING;
    out_b[3].buffer        = row_st;
    out_b[3].buffer_length = sizeof(row_st) - 1;
    out_b[3].length        = &slen;

    if (mysql_stmt_bind_result(s, out_b)) {
        mysql_stmt_close(s); db_pool_release(c); return 0;
    }

    int count = 0;
    while (mysql_stmt_fetch(s) == 0 && count < max) {
        row_un[ulen < sizeof(row_un)-1 ? ulen : sizeof(row_un)-1] = '\0';
        if (dn_null) row_dn[0] = '\0';
        else row_dn[dlen < sizeof(row_dn)-1 ? dlen : sizeof(row_dn)-1] = '\0';
        row_st[slen < sizeof(row_st)-1 ? slen : sizeof(row_st)-1] = '\0';

        out[count].id = row_id;
        snprintf(out[count].username, sizeof(out[count].username), "%s", row_un);
        snprintf(out[count].display_name, sizeof(out[count].display_name), "%s", row_dn);
        snprintf(out[count].status, sizeof(out[count].status), "%s", row_st);
        out[count].last_seen[0] = '\0';
        count++;
    }
    mysql_stmt_free_result(s);
    mysql_stmt_close(s);
    db_pool_release(c);
    return count;
}

int user_repo_get_profile(int uid,
                           char *out_username,     int uname_len,
                           char *out_display_name, int dn_len,
                           char *out_bio,          int bio_len,
                           char *out_status,       int status_len,
                           char *out_last_seen,    int last_seen_len,
                           int  *has_avatar)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[256];
    snprintf(q, sizeof(q),
             "SELECT username, display_name, bio,"
             " status, DATE_FORMAT(last_seen, '%%Y-%%m-%%d %%H:%%i:%%s'),"
             " (avatar IS NOT NULL) AS has_av"
             " FROM users WHERE id=%d LIMIT 1", uid);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return 0;
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return 0; }

    if (out_username)     { strncpy(out_username,     row[0] ? row[0] : "", uname_len - 1);  out_username[uname_len-1]     = '\0'; }
    if (out_display_name) { strncpy(out_display_name, row[1] ? row[1] : "", dn_len - 1);     out_display_name[dn_len-1]    = '\0'; }
    if (out_bio)          { strncpy(out_bio,          row[2] ? row[2] : "", bio_len - 1);    out_bio[bio_len-1]            = '\0'; }
    if (out_status)       { strncpy(out_status,       row[3] ? row[3] : "offline", status_len - 1); out_status[status_len-1] = '\0'; }
    if (out_last_seen)    { strncpy(out_last_seen,    row[4] ? row[4] : "", last_seen_len - 1); out_last_seen[last_seen_len-1] = '\0'; }
    if (has_avatar)       { *has_avatar = row[5] ? atoi(row[5]) : 0; }
    mysql_free_result(res);
    return 1;
}

int user_repo_find_hash_by_id(int uid, char *out_hash, int hash_len)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT password_hash FROM users WHERE id=%d LIMIT 1", uid);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return 0;
    MYSQL_ROW row = mysql_fetch_row(res);
    int found = 0;
    if (row && row[0]) {
        strncpy(out_hash, row[0], hash_len - 1);
        out_hash[hash_len - 1] = '\0';
        found = 1;
    }
    mysql_free_result(res);
    return found;
}

int user_repo_update_password(int uid, const char *stored_hash)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    const char *sql = "UPDATE users SET password_hash=? WHERE id=?";
    MYSQL_BIND b[2];
    memset(b, 0, sizeof(b));
    unsigned long hlen = (unsigned long)strlen(stored_hash);
    b[0].buffer_type   = MYSQL_TYPE_STRING;
    b[0].buffer        = (void *)stored_hash;
    b[0].buffer_length = hlen;
    b[1].buffer_type   = MYSQL_TYPE_LONG;
    b[1].buffer        = &uid;
    int rc = stmt_run_c(c, sql, b, 2) ? 0 : 1;
    db_pool_release(c);
    return rc;
}

int user_repo_get_privacy(int uid,
                          char *out_online,       int online_len,
                          char *out_last_seen,    int ls_len)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT privacy_online, privacy_last_seen"
             " FROM users WHERE id=%d LIMIT 1", uid);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return 0;
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return 0; }

    if (out_online)       { strncpy(out_online,       row[0] ? row[0] : "everyone", online_len - 1); out_online[online_len-1]       = '\0'; }
    if (out_last_seen)    { strncpy(out_last_seen,    row[1] ? row[1] : "everyone", ls_len - 1);     out_last_seen[ls_len-1]        = '\0'; }
    mysql_free_result(res);
    return 1;
}

int user_repo_update_privacy(int uid,
                              const char *online,
                              const char *last_seen)
{
    int has_online = online       && online[0];
    int has_ls     = last_seen    && last_seen[0];
    if (!has_online && !has_ls) return 1;

    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    int ok = 1;
    MYSQL_BIND b[2]; memset(b, 0, sizeof(b));
    b[1].buffer_type = MYSQL_TYPE_LONG;
    b[1].buffer      = (void *)&uid;

    if (has_online) {
        unsigned long len = (unsigned long)strlen(online);
        b[0].buffer_type   = MYSQL_TYPE_STRING;
        b[0].buffer        = (void *)online;
        b[0].buffer_length = len;
        if (stmt_run_c(c, "UPDATE users SET privacy_online=? WHERE id=?", b, 2))
            ok = 0;
    }
    if (has_ls) {
        unsigned long len = (unsigned long)strlen(last_seen);
        b[0].buffer_type   = MYSQL_TYPE_STRING;
        b[0].buffer        = (void *)last_seen;
        b[0].buffer_length = len;
        if (stmt_run_c(c, "UPDATE users SET privacy_last_seen=? WHERE id=?", b, 2))
            ok = 0;
    }
    db_pool_release(c);
    return ok;
}

unsigned char *user_repo_get_avatar(int uid, size_t *out_len, char *out_mime)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return NULL;

    char q[128];
    snprintf(q, sizeof(q),
             "SELECT avatar, avatar_mime FROM users WHERE id=%d LIMIT 1", uid);
    if (mysql_query(c, q)) { db_pool_release(c); return NULL; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return NULL;
    MYSQL_ROW     row    = mysql_fetch_row(res);
    unsigned long *lens  = mysql_fetch_lengths(res);
    if (!row || !row[0]) { mysql_free_result(res); return NULL; }

    size_t alen = lens[0];
    unsigned char *buf = (unsigned char *)malloc(alen);
    if (buf) {
        memcpy(buf, row[0], alen);
        *out_len = alen;
        if (out_mime) {
            strncpy(out_mime, row[1] ? row[1] : "image/jpeg", 63);
            out_mime[63] = '\0';
        }
    }
    mysql_free_result(res);
    return buf;
}
