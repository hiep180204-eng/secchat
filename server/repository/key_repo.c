/*
 * repository/key_repo.c — lưu/đọc public key material: identity key, bundle
 * PQXDH (signed prekey + one-time prekey), KeyPackage MLS và identity_key_log
 * (sổ append-only cho auditor). Server chỉ giữ public + secret đã mã hóa.
 */
#include "key_repo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mysql/mysql.h>

#include "db_pool.h"
#include "crypto.h"
#include "log.h"
#include "metrics.h"

/* MySQL C API reports transient connection drops through statement errno.
 * Retrying idempotent key uploads once is safe because these paths use
 * upsert or INSERT IGNORE semantics. */
#define MYSQL_ERR_SERVER_GONE 2006
#define MYSQL_ERR_SERVER_LOST 2013

/* Bind an optional string field (NULL if empty). */
#define BIND_OPT(b, ptr)                                              \
    do {                                                              \
        if ((ptr) && (ptr)[0]) {                                      \
            (b).buffer_type   = MYSQL_TYPE_STRING;                    \
            (b).buffer        = (void *)(ptr);                        \
            (b).buffer_length = (unsigned long)strlen(ptr);           \
        } else {                                                      \
            (b).buffer_type = MYSQL_TYPE_NULL;                        \
        }                                                             \
    } while (0)

static int stmt_run_c(MYSQL *c, const char *sql, MYSQL_BIND *b, unsigned int n)
{
    MYSQL_STMT *s = mysql_stmt_init(c);
    if (!s) return 1;
    if (mysql_stmt_prepare(s, sql, (unsigned long)strlen(sql))) {
        log_warn("key_repo stmt_prepare: %s", mysql_stmt_error(s));
        mysql_stmt_close(s); return 1;
    }
    if (n > 0 && mysql_stmt_bind_param(s, b)) {
        mysql_stmt_close(s); return 1;
    }
    uint64_t t0 = metrics_now_us();
    int rc = mysql_stmt_execute(s);
    unsigned int err = rc ? mysql_stmt_errno(s) : 0;
    metrics_lat_db_us(metrics_now_us() - t0);
    metrics_db_query(rc == 0);
    if (rc) log_warn("key_repo stmt_execute: %s", mysql_stmt_error(s));
    mysql_stmt_close(s);
    return err ? (int)err : rc;
}

static int key_stmt_retryable(int rc)
{
    return rc == MYSQL_ERR_SERVER_GONE || rc == MYSQL_ERR_SERVER_LOST;
}

/* â”€â”€ User keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

int key_upload_user(int uid,
                    const char *identity_pk_b64,  const char *identity_sig_b64,
                    const char *identity_sk_enc_b64)
{
    const char *sql =
        "INSERT INTO user_keys"
        "(user_id, identity_pk, identity_sig, identity_sk_enc)"
        " VALUES(?, ?, ?, ?)"
        " ON DUPLICATE KEY UPDATE"
        " identity_pk          = VALUES(identity_pk),"
        " identity_sig         = VALUES(identity_sig),"
        " identity_sk_enc      = VALUES(identity_sk_enc)";

    for (int attempt = 0; attempt < 2; attempt++) {
        MYSQL *c = db_pool_acquire();
        if (!c) return 0;

        MYSQL_BIND b[4];
        memset(b, 0, sizeof(b));

        b[0].buffer_type = MYSQL_TYPE_LONG;
        b[0].buffer      = &uid;

        BIND_OPT(b[1], identity_pk_b64);
        BIND_OPT(b[2], identity_sig_b64);
        BIND_OPT(b[3], identity_sk_enc_b64);

        int rc = stmt_run_c(c, sql, b, 4);
        db_pool_release(c);
        if (!rc) return 1;
        if (!key_stmt_retryable(rc)) return 0;
        log_warn("key_repo: retrying user key upload after MySQL reconnect error");
    }
    return 0;
}

int key_get_my_keys(int uid,
                    char *identity_pk,  int ipk_len,
                    char *identity_sig, int isig_len,
                    char *identity_sk_enc, int isk_len)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[256];
    snprintf(q, sizeof(q),
             "SELECT identity_pk, identity_sig, identity_sk_enc"
             " FROM user_keys WHERE user_id=%d LIMIT 1", uid);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    db_pool_release(c);
    if (!res) return 0;
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); return 0; }

    if (identity_pk)  { strncpy(identity_pk,   row[0] ? row[0] : "", ipk_len  - 1); identity_pk[ipk_len-1]   = '\0'; }
    if (identity_sig) { strncpy(identity_sig,  row[1] ? row[1] : "", isig_len - 1); identity_sig[isig_len-1] = '\0'; }
    if (identity_sk_enc){ strncpy(identity_sk_enc, row[2] ? row[2] : "", isk_len - 1); identity_sk_enc[isk_len-1] = '\0'; }
    mysql_free_result(res);
    return 1;
}

/* Identity versioning */

int key_bump_identity_version(int uid)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return -1;

    char q[256];
    snprintf(q, sizeof(q),
             "UPDATE user_keys SET identity_version = identity_version + 1"
             " WHERE user_id=%d", uid);
    if (mysql_query(c, q) || mysql_affected_rows(c) == 0) {
        db_pool_release(c);
        return -1;
    }

    /* Read back the new version in the same connection */
    snprintf(q, sizeof(q),
             "SELECT identity_version FROM user_keys WHERE user_id=%d LIMIT 1", uid);
    int version = -1;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0]) version = atoi(row[0]);
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    return version;
}

int key_get_identity_version(int uid)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return -1;
    char q[128];
    snprintf(q, sizeof(q),
             "SELECT identity_version FROM user_keys WHERE user_id=%d LIMIT 1", uid);
    int version = -1;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0]) version = atoi(row[0]);
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    return version;
}

int key_get_current_identity(int uid,
                             char *identity_pk, int identity_pk_len,
                             int *version_out)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT identity_pk, identity_version FROM user_keys"
             " WHERE user_id=%d AND identity_pk IS NOT NULL"
             "   AND identity_pk!='' LIMIT 1", uid);
    int found = 0;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0] && row[0][0]) {
                if (identity_pk && identity_pk_len > 0) {
                    strncpy(identity_pk, row[0], (size_t)identity_pk_len - 1);
                    identity_pk[identity_pk_len - 1] = '\0';
                }
                if (version_out) *version_out = row[1] ? atoi(row[1]) : 0;
                found = 1;
            }
            mysql_free_result(res);
        }
    }
    db_pool_release(c);
    return found;
}

static void utc_now_string(char out[32])
{
    time_t now = time(NULL);
    struct tm tmv;
#ifdef _WIN32
    gmtime_s(&tmv, &now);
#else
    gmtime_r(&now, &tmv);
#endif
    strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

int key_append_identity_log(int uid, int identity_version,
                            const char *identity_pk,
                            const char *device_id_hash,
                            const char *device_label,
                            const char *event_type,
                            char *leaf_hash_out, int leaf_hash_len)
{
    if (uid <= 0 || identity_version < 0 || !identity_pk || !identity_pk[0] ||
        !event_type || !event_type[0])
        return 0;

    const char *dev_hash = (device_id_hash && device_id_hash[0])
        ? device_id_hash : "";
    const char *dev_label = (device_label && device_label[0])
        ? device_label : "primary device";
    char created_at[32];
    utc_now_string(created_at);

    size_t canon_len = strlen(identity_pk) + strlen(dev_hash) +
        strlen(dev_label) + strlen(event_type) + 160;
    char *canon = (char *)malloc(canon_len);
    if (!canon) return 0;
    snprintf(canon, canon_len,
             "SecChatIdentityLeaf|%d|%d|%s|%s|%s|%s|%s",
             uid, identity_version, identity_pk, dev_hash, dev_label,
             event_type, created_at);
    char leaf_hash[65];
    sha256_hex(canon, leaf_hash);
    free(canon);

    MYSQL *c = db_pool_acquire();
    if (!c) return 0;
    const char *sql =
        "INSERT IGNORE INTO identity_key_log"
        "(user_id, identity_version, identity_pk, device_id_hash,"
        " device_label, event_type, created_at, leaf_hash)"
        " VALUES(?,?,?,?,?,?,?,?)";
    MYSQL_BIND b[8];
    memset(b, 0, sizeof(b));
    b[0].buffer_type = MYSQL_TYPE_LONG; b[0].buffer = &uid;
    b[1].buffer_type = MYSQL_TYPE_LONG; b[1].buffer = &identity_version;
    BIND_OPT(b[2], identity_pk);
    BIND_OPT(b[3], dev_hash);
    BIND_OPT(b[4], dev_label);
    BIND_OPT(b[5], event_type);
    b[6].buffer_type = MYSQL_TYPE_STRING;
    b[6].buffer = created_at;
    b[6].buffer_length = (unsigned long)strlen(created_at);
    b[7].buffer_type = MYSQL_TYPE_STRING;
    b[7].buffer = leaf_hash;
    b[7].buffer_length = (unsigned long)strlen(leaf_hash);
    int ok = stmt_run_c(c, sql, b, 8) ? 0 : 1;
    db_pool_release(c);

    if (ok && leaf_hash_out && leaf_hash_len > 0) {
        strncpy(leaf_hash_out, leaf_hash, (size_t)leaf_hash_len - 1);
        leaf_hash_out[leaf_hash_len - 1] = '\0';
    }
    return ok;
}

/* â”€â”€ SecChat PQXDH bundles â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

int key_pqxdh_upload_bundle(int uid,
                         const char *identity_pk,
                         int curve_spk_id,
                         const char *curve_spk,
                         const char *curve_spk_sig,
                         int pq_spk_id,
                         const char *pq_kem_alg,
                         const char *pq_spk,
                         const char *pq_spk_sig)
{
    const char *sql =
        "INSERT INTO pqxdh_bundles"
        "(user_id, identity_pk, curve_spk_id, curve_spk, curve_spk_sig,"
        " pq_spk_id, pq_kem_alg, pq_spk, pq_spk_sig, version)"
        " VALUES(?,?,?,?,?,?,?,?,?,2)"
        " ON DUPLICATE KEY UPDATE"
        " identity_pk=VALUES(identity_pk),"
        " curve_spk_id=VALUES(curve_spk_id),"
        " curve_spk=VALUES(curve_spk),"
        " curve_spk_sig=VALUES(curve_spk_sig),"
        " pq_spk_id=VALUES(pq_spk_id),"
        " pq_kem_alg=VALUES(pq_kem_alg),"
        " pq_spk=VALUES(pq_spk),"
        " pq_spk_sig=VALUES(pq_spk_sig),"
        " version=2";
    for (int attempt = 0; attempt < 2; attempt++) {
        MYSQL *c = db_pool_acquire();
        if (!c) return 0;
        MYSQL_BIND b[9];
        memset(b, 0, sizeof(b));
        b[0].buffer_type = MYSQL_TYPE_LONG; b[0].buffer = &uid;
        BIND_OPT(b[1], identity_pk);
        b[2].buffer_type = MYSQL_TYPE_LONG; b[2].buffer = &curve_spk_id;
        BIND_OPT(b[3], curve_spk);
        BIND_OPT(b[4], curve_spk_sig);
        b[5].buffer_type = MYSQL_TYPE_LONG; b[5].buffer = &pq_spk_id;
        BIND_OPT(b[6], pq_kem_alg);
        BIND_OPT(b[7], pq_spk);
        BIND_OPT(b[8], pq_spk_sig);
        int rc = stmt_run_c(c, sql, b, 9);
        if (!rc) {
            /* A fresh signed bundle defines a new OTK generation.  Keeping old OTK
             * rows lets get_pqxdh_bundle pair a new signed prekey with an old
             * one-time prekey, which produces an undecryptable PQXDH transcript. */
            char q[192];
            snprintf(q, sizeof(q),
                     "DELETE FROM pqxdh_curve_one_time_prekeys WHERE user_id=%d",
                     uid);
            mysql_query(c, q);
            snprintf(q, sizeof(q),
                     "DELETE FROM pqxdh_pq_one_time_prekeys WHERE user_id=%d",
                     uid);
            mysql_query(c, q);
            db_pool_release(c);
            return 1;
        }
        db_pool_release(c);
        if (!key_stmt_retryable(rc)) return 0;
        log_warn("key_repo: retrying PQXDH bundle upload after MySQL reconnect error");
    }
    return 0;
}

int key_pqxdh_upload_curve_otk(int uid, int key_id,
                            const char *public_key,
                            const char *signature)
{
    const char *sql =
        "INSERT IGNORE INTO pqxdh_curve_one_time_prekeys"
        "(user_id, key_id, public_key, signature) VALUES(?,?,?,?)";
    for (int attempt = 0; attempt < 2; attempt++) {
        MYSQL *c = db_pool_acquire();
        if (!c) return 0;
        MYSQL_BIND b[4];
        memset(b, 0, sizeof(b));
        b[0].buffer_type = MYSQL_TYPE_LONG; b[0].buffer = &uid;
        b[1].buffer_type = MYSQL_TYPE_LONG; b[1].buffer = &key_id;
        BIND_OPT(b[2], public_key);
        BIND_OPT(b[3], signature);
        int rc = stmt_run_c(c, sql, b, 4);
        db_pool_release(c);
        if (!rc) return 1;
        if (!key_stmt_retryable(rc)) return 0;
        log_warn("key_repo: retrying curve OTK upload after MySQL reconnect error");
    }
    return 0;
}

int key_pqxdh_upload_pq_otk(int uid, int key_id, const char *kem_alg,
                         const char *public_key,
                         const char *signature)
{
    const char *sql =
        "INSERT IGNORE INTO pqxdh_pq_one_time_prekeys"
        "(user_id, key_id, kem_alg, public_key, signature) VALUES(?,?,?,?,?)";
    for (int attempt = 0; attempt < 2; attempt++) {
        MYSQL *c = db_pool_acquire();
        if (!c) return 0;
        MYSQL_BIND b[5];
        memset(b, 0, sizeof(b));
        b[0].buffer_type = MYSQL_TYPE_LONG; b[0].buffer = &uid;
        b[1].buffer_type = MYSQL_TYPE_LONG; b[1].buffer = &key_id;
        BIND_OPT(b[2], kem_alg);
        BIND_OPT(b[3], public_key);
        BIND_OPT(b[4], signature);
        int rc = stmt_run_c(c, sql, b, 5);
        db_pool_release(c);
        if (!rc) return 1;
        if (!key_stmt_retryable(rc)) return 0;
        log_warn("key_repo: retrying PQ OTK upload after MySQL reconnect error");
    }
    return 0;
}

static int count_current_pqxdh_otks(MYSQL *c, const char *table,
                                 int uid, int signed_key_id)
{
    if (signed_key_id <= 0)
        return 0;
    char q[256];
    snprintf(q, sizeof(q),
             "SELECT COUNT(*) FROM %s"
             " WHERE user_id=%d AND key_id>%d AND key_id<=%d",
             table, uid, signed_key_id, signed_key_id + 1024);
    int n = 0;
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row && row[0]) n = atoi(row[0]);
            mysql_free_result(res);
        }
    }
    return n;
}

int key_pqxdh_get_status(int uid, int *has_bundle_out,
                      int *curve_count_out, int *pq_count_out)
{
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    int has_bundle = 0;
    int curve_spk_id = 0;
    int pq_spk_id = 0;
    char q[192];
    snprintf(q, sizeof(q),
             "SELECT curve_spk_id, pq_spk_id FROM pqxdh_bundles"
             " WHERE user_id=%d LIMIT 1", uid);
    if (mysql_query(c, q) == 0) {
        MYSQL_RES *res = mysql_store_result(c);
        if (res) {
            MYSQL_ROW row = mysql_fetch_row(res);
            if (row) {
                has_bundle = 1;
                curve_spk_id = row[0] ? atoi(row[0]) : 0;
                pq_spk_id = row[1] ? atoi(row[1]) : 0;
            }
            mysql_free_result(res);
        }
    } else {
        db_pool_release(c);
        return 0;
    }

    if (has_bundle_out) *has_bundle_out = has_bundle;
    if (curve_count_out)
        *curve_count_out = count_current_pqxdh_otks(
            c, "pqxdh_curve_one_time_prekeys", uid, curve_spk_id);
    if (pq_count_out)
        *pq_count_out = count_current_pqxdh_otks(
            c, "pqxdh_pq_one_time_prekeys", uid, pq_spk_id);

    db_pool_release(c);
    return 1;
}

int key_pqxdh_get_bundle_consuming(int target_uid, PqxdhBundleRecord *out)
{
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    out->curve_otk_id = -1;
    out->pq_otk_id = -1;
    MYSQL *c = db_pool_acquire();
    if (!c) return 0;

    char q[512];
    snprintf(q, sizeof(q),
             "SELECT identity_pk, curve_spk_id, curve_spk, curve_spk_sig,"
             " pq_spk_id, pq_kem_alg, pq_spk, pq_spk_sig"
             " FROM pqxdh_bundles WHERE user_id=%d LIMIT 1", target_uid);
    if (mysql_query(c, q)) { db_pool_release(c); return 0; }
    MYSQL_RES *res = mysql_store_result(c);
    if (!res) { db_pool_release(c); return 0; }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) { mysql_free_result(res); db_pool_release(c); return 0; }
    strncpy(out->identity_pk, row[0] ? row[0] : "", sizeof(out->identity_pk)-1);
    out->curve_spk_id = row[1] ? atoi(row[1]) : 0;
    strncpy(out->curve_spk, row[2] ? row[2] : "", sizeof(out->curve_spk)-1);
    strncpy(out->curve_spk_sig, row[3] ? row[3] : "", sizeof(out->curve_spk_sig)-1);
    out->pq_spk_id = row[4] ? atoi(row[4]) : 0;
    strncpy(out->pq_kem_alg, row[5] ? row[5] : "", sizeof(out->pq_kem_alg)-1);
    strncpy(out->pq_spk, row[6] ? row[6] : "", sizeof(out->pq_spk)-1);
    strncpy(out->pq_spk_sig, row[7] ? row[7] : "", sizeof(out->pq_spk_sig)-1);
    mysql_free_result(res);

    snprintf(q, sizeof(q),
             "SELECT id, key_id, public_key, signature"
             " FROM pqxdh_curve_one_time_prekeys"
             " WHERE user_id=%d AND key_id>%d AND key_id<=%d"
             " ORDER BY id ASC LIMIT 1",
             target_uid, out->curve_spk_id, out->curve_spk_id + 1024);
    if (mysql_query(c, q) == 0) {
        res = mysql_store_result(c);
        if (res) {
            row = mysql_fetch_row(res);
            if (row) {
                long long row_id = row[0] ? atoll(row[0]) : 0;
                out->curve_otk_id = row[1] ? atoi(row[1]) : -1;
                strncpy(out->curve_otk, row[2] ? row[2] : "", sizeof(out->curve_otk)-1);
                strncpy(out->curve_otk_sig, row[3] ? row[3] : "", sizeof(out->curve_otk_sig)-1);
                if (row_id > 0) {
                    char dq[128];
                    snprintf(dq, sizeof(dq),
                             "DELETE FROM pqxdh_curve_one_time_prekeys WHERE id=%lld",
                             row_id);
                    mysql_query(c, dq);
                }
            }
            mysql_free_result(res);
        }
    }

    snprintf(q, sizeof(q),
             "SELECT id, key_id, kem_alg, public_key, signature"
             " FROM pqxdh_pq_one_time_prekeys"
             " WHERE user_id=%d AND key_id>%d AND key_id<=%d"
             " ORDER BY id ASC LIMIT 1",
             target_uid, out->pq_spk_id, out->pq_spk_id + 1024);
    if (mysql_query(c, q) == 0) {
        res = mysql_store_result(c);
        if (res) {
            row = mysql_fetch_row(res);
            if (row) {
                long long row_id = row[0] ? atoll(row[0]) : 0;
                out->pq_otk_id = row[1] ? atoi(row[1]) : -1;
                strncpy(out->pq_otk_alg, row[2] ? row[2] : "", sizeof(out->pq_otk_alg)-1);
                strncpy(out->pq_otk, row[3] ? row[3] : "", sizeof(out->pq_otk)-1);
                strncpy(out->pq_otk_sig, row[4] ? row[4] : "", sizeof(out->pq_otk_sig)-1);
                if (row_id > 0) {
                    char dq[128];
                    snprintf(dq, sizeof(dq),
                             "DELETE FROM pqxdh_pq_one_time_prekeys WHERE id=%lld",
                             row_id);
                    mysql_query(c, dq);
                }
            }
            mysql_free_result(res);
        }
    }

    out->curve_pool = count_current_pqxdh_otks(
        c, "pqxdh_curve_one_time_prekeys", target_uid, out->curve_spk_id);
    out->pq_pool = count_current_pqxdh_otks(
        c, "pqxdh_pq_one_time_prekeys", target_uid, out->pq_spk_id);
    db_pool_release(c);
    return out->identity_pk[0] && out->curve_spk[0] && out->pq_spk[0];
}

#undef BIND_OPT
