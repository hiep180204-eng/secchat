/*
 * services/keys.c â€” bounded context quáº£n lÃ½ khÃ³a.
 *
 * Server chá»‰ lÆ°u public key, encrypted secret key vÃ  prekey bundle do client
 * upload. Server khÃ´ng cÃ³ master key cá»§a client nÃªn khÃ´ng thá»ƒ giáº£i mÃ£ secret
 * key Ä‘Æ°á»£c lÆ°u á»Ÿ Ä‘Ã¢y.
 *
 * upload_keys cÃ´ng bá»‘ identity record Ed25519 cá»§a account. rotate_identity lÃ 
 * Ä‘Æ°á»ng duy nháº¥t Ä‘Æ°á»£c phÃ©p Ä‘á»•i identity key tháº­t sá»±. upload_pqxdh_bundle
 * Ä‘Äƒng public bundle SecChat Ä‘á»ƒ ngÆ°á»i khÃ¡c báº¯t Ä‘áº§u DM báº±ng PQXDH.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mysql/mysql.h>
#include <openssl/evp.h>

#include "keys.h"
#include "clients.h"
#include "json_helpers.h"
#include "log.h"
#include "key_repo.h"
#include "friendship_repo.h"
#include "conversation_repo.h"
#include "db_pool.h"
#include "cJSON.h"

#define SECCHAT_MLS_PQ_CIPHERSUITE "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"

static int b64_decode_alloc(const char *text, unsigned char **out, size_t *out_len)
{
    if (!text || !out || !out_len) return 0;
    *out = NULL;
    *out_len = 0;

    size_t in_len = strlen(text);
    char *norm = (char *)malloc(in_len + 5);
    if (!norm) return 0;
    size_t n = 0;
    for (size_t i = 0; i < in_len; i++) {
        char ch = text[i];
        if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t')
            continue;
        if (ch == '-') ch = '+';
        else if (ch == '_') ch = '/';
        norm[n++] = ch;
    }
    size_t rem = n % 4;
    if (rem == 1) {
        free(norm);
        return 0;
    }
    size_t pad = (4 - rem) % 4;
    for (size_t i = 0; i < pad; i++)
        norm[n++] = '=';
    norm[n] = '\0';

    unsigned char *decoded = (unsigned char *)malloc((n / 4) * 3 + 4);
    if (!decoded) {
        free(norm);
        return 0;
    }
    int written = EVP_DecodeBlock(decoded, (const unsigned char *)norm, (int)n);
    if (written < 0) {
        free(decoded);
        free(norm);
        return 0;
    }
    size_t eq = 0;
    while (eq < n && norm[n - 1 - eq] == '=')
        eq++;
    if ((size_t)written < eq) {
        free(decoded);
        free(norm);
        return 0;
    }
    *out = decoded;
    *out_len = (size_t)written - eq;
    free(norm);
    return 1;
}

static int verify_ed25519_b64(const char *identity_pk_b64, const char *sig_b64,
                              const unsigned char *message, size_t message_len)
{
    unsigned char *pk = NULL;
    unsigned char *sig = NULL;
    size_t pk_len = 0, sig_len = 0;
    int ok = 0;
    if (!b64_decode_alloc(identity_pk_b64, &pk, &pk_len) ||
        !b64_decode_alloc(sig_b64, &sig, &sig_len) ||
        pk_len != 32 || sig_len != 64) {
        goto done;
    }
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, pk_len);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!pkey || !ctx) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        goto done;
    }
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
        EVP_DigestVerify(ctx, sig, sig_len, message, message_len) == 1) {
        ok = 1;
    }
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
done:
    free(pk);
    free(sig);
    return ok;
}

static int verify_mls_key_package_signature(int uid, const char *ref,
                                            const char *key_package_b64,
                                            const char *ciphersuite,
                                            const char *signature_b64)
{
    if (uid <= 0 || !ref || !ref[0] || !key_package_b64 || !key_package_b64[0] ||
        !ciphersuite || !ciphersuite[0] || !signature_b64 || !signature_b64[0])
        return 0;

    char identity_pk[512] = {0};
    int version = 0;
    if (!key_get_current_identity(uid, identity_pk, sizeof(identity_pk), &version) ||
        !identity_pk[0]) {
        return 0;
    }
    (void)version;

    const char prefix[] = "SecChatMLSKeyPackage";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t ref_len = strlen(ref);
    size_t kp_len = strlen(key_package_b64);
    size_t cs_len = strlen(ciphersuite);
    size_t msg_len = prefix_len + 1 + ref_len + 1 + kp_len + 1 + cs_len;
    unsigned char *msg = (unsigned char *)malloc(msg_len);
    if (!msg) return 0;
    size_t pos = 0;
    memcpy(msg + pos, prefix, prefix_len); pos += prefix_len;
    msg[pos++] = '\0';
    memcpy(msg + pos, ref, ref_len); pos += ref_len;
    msg[pos++] = '\0';
    memcpy(msg + pos, key_package_b64, kp_len); pos += kp_len;
    msg[pos++] = '\0';
    memcpy(msg + pos, ciphersuite, cs_len);

    int ok = verify_ed25519_b64(identity_pk, signature_b64, msg, msg_len);
    free(msg);
    return ok;
}

static void canonical_identity_b64(const char *in, char *out, size_t out_sz)
{
    /* Chuáº©n hÃ³a base64 identity Ä‘á»ƒ so sÃ¡nh bytes theo biá»ƒu diá»…n tÆ°Æ¡ng Ä‘Æ°Æ¡ng:
     * base64 chuáº©n/url-safe, cÃ³ padding hoáº·c khÃ´ng padding. */
    if (!out || out_sz == 0) return;
    out[0] = '\0';
    if (!in) return;
    size_t pos = 0;
    for (const char *p = in; *p && pos + 1 < out_sz; p++) {
        char ch = *p;
        if (ch == '-') ch = '+';
        else if (ch == '_') ch = '/';
        if (ch == '=' || ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t')
            continue;
        out[pos++] = ch;
    }
    out[pos] = '\0';
}

static int identity_b64_equal(const char *a, const char *b)
{
    /* TrÃ¡nh lá»—i giáº£ "Identity change requires rotate_identity" khi cÃ¹ng má»™t
     * key Ä‘Æ°á»£c client gá»­i báº±ng hai kiá»ƒu base64 khÃ¡c nhau. */
    char ca[512], cb[512];
    canonical_identity_b64(a, ca, sizeof(ca));
    canonical_identity_b64(b, cb, sizeof(cb));
    return ca[0] && cb[0] && strcmp(ca, cb) == 0;
}

static void bind_nullable_text(MYSQL_BIND *b, const char *text)
{
    memset(b, 0, sizeof(*b));
    if (text && text[0]) {
        b->buffer_type = MYSQL_TYPE_STRING;
        b->buffer = (void *)text;
        b->buffer_length = (unsigned long)strlen(text);
    } else {
        b->buffer_type = MYSQL_TYPE_NULL;
    }
}

static int mls_insert_key_package(int uid, const char *ref,
                                  const char *ciphersuite,
                                  const char *credential_identity_b64,
                                  const char *key_package_b64,
                                  int identity_version,
                                  const char *secchat_signature)
{
    if (uid <= 0 || !ref || !ref[0] || !ciphersuite || !ciphersuite[0] ||
        !key_package_b64 || !key_package_b64[0])
        return 0;
    MYSQL *conn = db_pool_acquire();
    if (!conn) return 0;
    const char *sql =
        "INSERT INTO mls_key_packages"
        "(user_id,key_package_ref,ciphersuite,credential_identity_b64,"
        " key_package_b64,secchat_identity_version,secchat_signature)"
        " VALUES(?,?,?,?,?,?,?)"
        " ON DUPLICATE KEY UPDATE"
        " ciphersuite=VALUES(ciphersuite),"
        " credential_identity_b64=VALUES(credential_identity_b64),"
        " key_package_b64=VALUES(key_package_b64),"
        " secchat_identity_version=VALUES(secchat_identity_version),"
        " secchat_signature=VALUES(secchat_signature),"
        " claimed_at=NULL, claimed_by=NULL";
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt) { db_pool_release(conn); return 0; }
    if (mysql_stmt_prepare(stmt, sql, (unsigned long)strlen(sql))) {
        log_warn("mls_insert_key_package prepare: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt); db_pool_release(conn); return 0;
    }
    MYSQL_BIND b[7];
    memset(b, 0, sizeof(b));
    b[0].buffer_type = MYSQL_TYPE_LONG; b[0].buffer = &uid;
    b[1].buffer_type = MYSQL_TYPE_STRING; b[1].buffer = (void *)ref;
    b[1].buffer_length = (unsigned long)strlen(ref);
    b[2].buffer_type = MYSQL_TYPE_STRING; b[2].buffer = (void *)ciphersuite;
    b[2].buffer_length = (unsigned long)strlen(ciphersuite);
    bind_nullable_text(&b[3], credential_identity_b64);
    b[4].buffer_type = MYSQL_TYPE_STRING; b[4].buffer = (void *)key_package_b64;
    b[4].buffer_length = (unsigned long)strlen(key_package_b64);
    b[5].buffer_type = MYSQL_TYPE_LONG; b[5].buffer = &identity_version;
    bind_nullable_text(&b[6], secchat_signature);
    int ok = !(mysql_stmt_bind_param(stmt, b) || mysql_stmt_execute(stmt));
    if (!ok) log_warn("mls_insert_key_package exec: %s", mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    db_pool_release(conn);
    return ok;
}

static void mls_discard_unclaimed_key_packages(int uid)
{
    if (uid <= 0) return;
    MYSQL *conn = db_pool_acquire();
    if (!conn) return;
    char q[160];
    snprintf(q, sizeof(q),
             "DELETE FROM mls_key_packages"
             " WHERE user_id=%d AND claimed_at IS NULL",
             uid);
    if (mysql_query(conn, q))
        log_warn("mls_discard_unclaimed_key_packages: %s",
                 mysql_error(conn));
    db_pool_release(conn);
}

/* â”€â”€ upload_keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

static void handle_upload_keys(int idx, const char *buf)
{
    /* Náº¿u account Ä‘Ã£ cÃ³ identity key vÃ  client gá»­i key khÃ¡c,
     * server tá»« chá»‘i Ä‘á»ƒ buá»™c dÃ¹ng rotate_identity, nhá» váº­y má»i key change Ä‘á»u
     * cÃ³ event rÃµ rÃ ng cho client vÃ  auditor. */
    int my_uid = clients_get_uid(idx);

    char id_pk[256]     = {0}, id_sig[256]    = {0};
    char id_sk_enc[8192]= {0};

    jget(buf, "identity_pk",   id_pk,      sizeof(id_pk));
    jget(buf, "identity_sig",  id_sig,     sizeof(id_sig));
    jget(buf, "identity_sk_enc", id_sk_enc, sizeof(id_sk_enc));

    if (!id_pk[0]) return;

    {
        char current_id[256] = {0};
        int current_version = 0;
        if (key_get_current_identity(my_uid, current_id, sizeof(current_id),
                                     &current_version)
                && !identity_b64_equal(current_id, id_pk)) {
            clients_send(idx,
                "{\"type\":\"error\",\"msg\":\"Identity change requires rotate_identity\"}");
            return;
        }
    }

    if (key_upload_user(my_uid, id_pk, id_sig, id_sk_enc)) {
        int version = key_get_identity_version(my_uid);
        char leaf_hash[65] = {0};
        key_append_identity_log(
            my_uid, version >= 0 ? version : 0, id_pk,
            "", "primary device", "initial",
            leaf_hash, sizeof(leaf_hash));
        clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Keys uploaded\"}");
    } else {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to upload keys\"}");
    }
}



/* â”€â”€ get_my_keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

/* Trả bundle khóa của CHÍNH client (public + secret đã mã hóa) để khôi phục state sau login. */
static void handle_get_my_keys(int idx)
{
    int my_uid = clients_get_uid(idx);

    char identity_pk[256]   = {0};
    char identity_sig[256]  = {0};
    char identity_sk_enc[8192] = {0};

    if (!key_get_my_keys(my_uid,
                         identity_pk,  sizeof(identity_pk),
                         identity_sig, sizeof(identity_sig),
                         identity_sk_enc, sizeof(identity_sk_enc))) {
        clients_send(idx, "{\"type\":\"my_keys\",\"found\":false}");
        return;
    }

    int version = key_get_identity_version(my_uid);

    size_t resp_sz = strlen(identity_pk) + strlen(identity_sig) +
                     strlen(identity_sk_enc) + 256;
    char *resp = (char *)malloc(resp_sz);
    if (!resp) return;
    snprintf(resp, resp_sz,
             "{\"type\":\"my_keys\",\"found\":true,"
             "\"identity_pk\":\"%s\","
             "\"identity_sig\":\"%s\","
             "\"identity_sk_enc\":\"%s\","
             "\"identity_version\":%d}",
             identity_pk, identity_sig, identity_sk_enc,
             version >= 0 ? version : 0);
    clients_send(idx, resp);
    free(resp);
}

/* â”€â”€ get_my_pqxdh_status â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

static void handle_get_my_pqxdh_status(int idx)
{
    int my_uid = clients_get_uid(idx);
    int has_bundle = 0, curve_count = 0, pq_count = 0;
    if (!key_pqxdh_get_status(my_uid, &has_bundle, &curve_count, &pq_count)) {
        clients_send(idx,
            "{\"type\":\"error\",\"msg\":\"Failed to load PQXDH status\"}");
        return;
    }
    int identity_version = key_get_identity_version(my_uid);
    char resp[192];
    snprintf(resp, sizeof(resp),
             "{\"type\":\"pqxdh_status\",\"has_bundle\":%s,"
             "\"curve_prekeys\":%d,\"pq_prekeys\":%d,"
             "\"identity_version\":%d}",
             has_bundle ? "true" : "false",
             curve_count, pq_count,
             identity_version >= 0 ? identity_version : 0);
    clients_send(idx, resp);
}

/* â”€â”€ rotate_identity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
/*
 * Full key rotation: replaces the stored key bundle and bumps identity_version.
 * Sends identity_changed to all online friends.
 * Sends safety_number_changed to each DM partner (both online and offline
 * representation â€” the partner will see it on next inbox load or live if
 * currently connected).
 */
static void handle_rotate_identity(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);

    char id_pk[256]      = {0}, id_sig[256]     = {0};
    char id_sk_enc[8192] = {0};

    jget(buf, "identity_pk",   id_pk,      sizeof(id_pk));
    jget(buf, "identity_sig",  id_sig,     sizeof(id_sig));
    jget(buf, "identity_sk_enc", id_sk_enc, sizeof(id_sk_enc));

    if (!id_pk[0]) {
        clients_send(idx,
            "{\"type\":\"error\",\"msg\":\"Identity key required for rotation\"}");
        return;
    }

    /* 1. Upsert new identity key record */
    if (!key_upload_user(my_uid, id_pk, id_sig, id_sk_enc)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to update keys\"}");
        return;
    }

    /* 2. Atomically bump identity_version */
    int new_version = key_bump_identity_version(my_uid);
    if (new_version < 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to bump version\"}");
        return;
    }

    char leaf_hash[65] = {0};
    key_append_identity_log(
        my_uid, new_version, id_pk,
        "", "primary device", "rotation",
        leaf_hash, sizeof(leaf_hash));

    clients_send(idx,
        "{\"type\":\"ok\",\"msg\":\"Identity rotated\"}");
    log_info("keys: uid=%d rotated identity â†’ version=%d", my_uid, new_version);

    /* 3. Notify all friends: identity_changed */
    FriendRecord friends[200];
    int n_friends = friendship_list_for_user(my_uid, friends, 200);

    char id_notif[512];
    snprintf(id_notif, sizeof(id_notif),
             "{\"type\":\"identity_changed\","
             "\"user_id\":%d,"
             "\"identity_pk\":\"%s\","
             "\"identity_version\":%d}",
             my_uid, id_pk, new_version);

    for (int i = 0; i < n_friends; i++)
        clients_send_to_uid(friends[i].id, id_notif);

    /* 4. Send safety_number_changed to each DM partner */
    int dm_partners[200];
    int n_dm = conv_get_dm_partners(my_uid, dm_partners, 200);
    for (int i = 0; i < n_dm; i++) {
        char sn_notif[512];
        snprintf(sn_notif, sizeof(sn_notif),
                 "{\"type\":\"safety_number_changed\","
                 "\"user_id\":%d,"
                 "\"identity_pk\":\"%s\","
                 "\"identity_version\":%d}",
                 my_uid, id_pk, new_version);
        clients_send_to_uid(dm_partners[i], sn_notif);
    }
}

static const char *json_str(cJSON *obj, const char *name)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    return (cJSON_IsString(item) && item->valuestring) ? item->valuestring : "";
}

static int json_int(cJSON *obj, const char *name, int def)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, name);
    return cJSON_IsNumber(item) ? item->valueint : def;
}

/* â”€â”€ upload_mls_key_packages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

/*
 * Nhận và lưu các KeyPackage MLS (public, single-use) client đăng lên.
 * Mỗi package phải đúng ciphersuite X-Wing và có chữ ký SecChat hợp lệ; package
 * không hợp lệ bị bỏ. Trước khi nhận batch mới, hủy các package cũ chưa được
 * claim để tránh người khác tạo Welcome cho package mà private key đã mất.
 */
static void handle_upload_mls_key_packages(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid JSON\"}");
        return;
    }
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "key_packages");
    if (!cJSON_IsArray(arr)) {
        cJSON_Delete(root);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Missing key_packages array\"}");
        return;
    }
    int identity_version = key_get_identity_version(my_uid);
    if (identity_version < 0) identity_version = 0;

    /* MLS KeyPackage private state lives on the active client runtime until
     * E2EE backup/restore is imported. In this reset-clean product flow we
     * support one active MLS device per account, so unclaimed packages from
     * older logins must not be handed out after the user publishes a fresh
     * batch. Otherwise another member can create a Welcome for a package whose
     * private key no longer exists on the current VNC, producing
     * NoMatchingKeyPackage on join. */
    mls_discard_unclaimed_key_packages(my_uid);

    int inserted = 0;
    int seen = 0;
    int rejected = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (!cJSON_IsObject(item)) continue;
        seen++;
        const char *ref = json_str(item, "key_package_ref");
        const char *kp = json_str(item, "key_package_b64");
        const char *cs = json_str(item, "ciphersuite");
        const char *cred = json_str(item, "credential_identity_b64");
        const char *sig = json_str(item, "secchat_signature");
        if (!ref[0] || !kp[0] ||
            strcmp(cs, SECCHAT_MLS_PQ_CIPHERSUITE) != 0 ||
            !verify_mls_key_package_signature(my_uid, ref, kp, cs, sig)) {
            rejected++;
            continue;
        }
        if (mls_insert_key_package(my_uid, ref, cs, cred, kp,
                                   identity_version, sig))
            inserted++;
    }
    cJSON_Delete(root);
    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"type\":\"mls_key_packages_uploaded\",\"received\":%d,"
             "\"stored\":%d,\"rejected\":%d,\"ciphersuite\":\"%s\"}",
             seen, inserted, rejected, SECCHAT_MLS_PQ_CIPHERSUITE);
    clients_send(idx, resp);
}

/* â”€â”€ claim_mls_key_package â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

/*
 * Cấp MỘT KeyPackage của một bạn bè (target_uid) cho người muốn add họ vào group.
 * Chỉ claim được KeyPackage của bạn bè; server trả public package để client tự
 * dựng Welcome — server không tạo Welcome.
 */
static void handle_claim_mls_key_package(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);
    int target_uid = 0;
    jget_int(buf, "user_id", &target_uid);
    if (target_uid <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid user_id\"}");
        return;
    }
    if (target_uid != my_uid && !friendship_exists_accepted(my_uid, target_uid)) {
        clients_send(idx,
            "{\"type\":\"error\",\"msg\":\"Can only claim KeyPackage for friends\"}");
        return;
    }

    MYSQL *conn = db_pool_acquire();
    if (!conn) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"DB unavailable\"}");
        return;
    }
    mysql_query(conn, "START TRANSACTION");
    char q[512];
    snprintf(q, sizeof(q),
             "SELECT id,key_package_ref,ciphersuite,credential_identity_b64,"
             " key_package_b64,secchat_identity_version"
             " FROM mls_key_packages"
             " WHERE user_id=%d AND claimed_at IS NULL"
             "   AND ciphersuite='%s'"
             " ORDER BY id ASC LIMIT 1 FOR UPDATE",
             target_uid, SECCHAT_MLS_PQ_CIPHERSUITE);
    if (mysql_query(conn, q)) {
        mysql_query(conn, "ROLLBACK");
        db_pool_release(conn);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to claim KeyPackage\"}");
        return;
    }
    MYSQL_RES *res = mysql_store_result(conn);
    if (!res) {
        mysql_query(conn, "ROLLBACK");
        db_pool_release(conn);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to claim KeyPackage\"}");
        return;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (!row) {
        mysql_free_result(res);
        mysql_query(conn, "COMMIT");
        db_pool_release(conn);
        char resp[96];
        snprintf(resp, sizeof(resp),
                 "{\"type\":\"mls_key_package\",\"found\":false,\"user_id\":%d}",
                 target_uid);
        clients_send(idx, resp);
        return;
    }
    long long package_id = row[0] ? atoll(row[0]) : 0;
    const char *ref = row[1] ? row[1] : "";
    const char *cs = row[2] ? row[2] : "";
    const char *cred = row[3] ? row[3] : "";
    const char *kp = row[4] ? row[4] : "";
    int identity_version = row[5] ? atoi(row[5]) : 0;

    char *ref_copy = strdup(ref);
    char *cs_copy = strdup(cs);
    char *cred_copy = strdup(cred);
    char *kp_copy = strdup(kp);
    mysql_free_result(res);
    if (!ref_copy || !cs_copy || !cred_copy || !kp_copy) {
        free(ref_copy); free(cs_copy); free(cred_copy); free(kp_copy);
        mysql_query(conn, "ROLLBACK");
        db_pool_release(conn);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server memory error\"}");
        return;
    }
    snprintf(q, sizeof(q),
             "UPDATE mls_key_packages SET claimed_at=NOW(3), claimed_by=%d"
             " WHERE id=%lld AND claimed_at IS NULL",
             my_uid, package_id);
    if (mysql_query(conn, q) || mysql_affected_rows(conn) == 0) {
        free(ref_copy); free(cs_copy); free(cred_copy); free(kp_copy);
        mysql_query(conn, "ROLLBACK");
        db_pool_release(conn);
        char resp[96];
        snprintf(resp, sizeof(resp),
                 "{\"type\":\"mls_key_package\",\"found\":false,\"user_id\":%d}",
                 target_uid);
        clients_send(idx, resp);
        return;
    }
    mysql_query(conn, "COMMIT");
    db_pool_release(conn);

    size_t resp_sz = strlen(ref_copy) + strlen(cs_copy) + strlen(cred_copy)
                   + strlen(kp_copy) + 512;
    char *resp = (char *)malloc(resp_sz);
    if (!resp) {
        free(ref_copy); free(cs_copy); free(cred_copy); free(kp_copy);
        return;
    }
    char *esc_ref = (char *)malloc(strlen(ref_copy) * 2 + 8);
    char *esc_cs = (char *)malloc(strlen(cs_copy) * 2 + 8);
    char *esc_cred = (char *)malloc(strlen(cred_copy) * 2 + 8);
    char *esc_kp = (char *)malloc(strlen(kp_copy) * 2 + 8);
    if (!esc_ref || !esc_cs || !esc_cred || !esc_kp) {
        free(resp); free(esc_ref); free(esc_cs); free(esc_cred); free(esc_kp);
        free(ref_copy); free(cs_copy); free(cred_copy); free(kp_copy);
        return;
    }
    json_esc(ref_copy, esc_ref, (int)(strlen(ref_copy) * 2 + 8));
    json_esc(cs_copy, esc_cs, (int)(strlen(cs_copy) * 2 + 8));
    json_esc(cred_copy, esc_cred, (int)(strlen(cred_copy) * 2 + 8));
    json_esc(kp_copy, esc_kp, (int)(strlen(kp_copy) * 2 + 8));
    snprintf(resp, resp_sz,
             "{\"type\":\"mls_key_package\",\"found\":true,"
             "\"user_id\":%d,\"key_package_ref\":\"%s\","
             "\"ciphersuite\":\"%s\",\"credential_identity_b64\":\"%s\","
             "\"key_package_b64\":\"%s\","
             "\"secchat_identity_version\":%d}",
             target_uid, esc_ref, esc_cs, esc_cred, esc_kp,
             identity_version);
    clients_send(idx, resp);
    free(resp); free(esc_ref); free(esc_cs); free(esc_cred); free(esc_kp);
    free(ref_copy); free(cs_copy); free(cred_copy); free(kp_copy);
}

static int pqxdh_kem_allowed(const char *alg)
{
    /* KEM Ä‘Æ°á»£c client khai bÃ¡o pháº£i náº±m trong danh sÃ¡ch cho phÃ©p Ä‘á»ƒ trÃ¡nh
     * downgrade sang thuáº­t toÃ¡n khÃ´ng Ä‘Æ°á»£c thiáº¿t káº¿/test trong SecChat. */
    return alg && (
        strcmp(alg, "ML-KEM-1024") == 0 ||
        strcmp(alg, "Kyber1024") == 0 ||
        strcmp(alg, "ML-KEM-768") == 0 ||
        strcmp(alg, "Kyber768") == 0
    );
}

/* â”€â”€ upload_pqxdh_bundle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

static void handle_upload_pqxdh_bundle(int idx, const char *buf)
{
    /* Client upload public PQXDH bundle gá»“m signed curve prekey, signed PQ KEM
     * prekey vÃ  cÃ¡c one-time prekey. Server khÃ´ng kiá»ƒm tra chá»¯ kÃ½ prekey á»Ÿ Ä‘Ã¢y;
     * chá»¯ kÃ½ Ä‘Æ°á»£c client nháº­n bundle kiá»ƒm tra trÆ°á»›c khi dÃ¹ng. */
    int my_uid = clients_get_uid(idx);
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid JSON\"}");
        return;
    }

    const char *identity_pk = json_str(root, "identity_pk");
    int curve_spk_id = json_int(root, "curve_spk_id", 0);
    const char *curve_spk = json_str(root, "curve_spk");
    const char *curve_spk_sig = json_str(root, "curve_spk_sig");
    int pq_spk_id = json_int(root, "pq_spk_id", 0);
    const char *pq_alg = json_str(root, "pq_kem_alg");
    const char *pq_spk = json_str(root, "pq_spk");
    const char *pq_spk_sig = json_str(root, "pq_spk_sig");

    if (!identity_pk[0] || curve_spk_id <= 0 || !curve_spk[0] ||
        !curve_spk_sig[0] || pq_spk_id <= 0 || !pqxdh_kem_allowed(pq_alg) ||
        !pq_spk[0] || !pq_spk_sig[0]) {
        cJSON_Delete(root);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid PQXDH bundle\"}");
        return;
    }

    char current_id[256] = {0};
    int current_version = 0;
    if (key_get_current_identity(my_uid, current_id, sizeof(current_id),
                                 &current_version)) {
        /* Bundle PQXDH pháº£i gáº¯n vá»›i identity hiá»‡n táº¡i. Náº¿u key tháº­t sá»± khÃ¡c, chá»‰
         * rotate_identity má»›i Ä‘Æ°á»£c Ä‘á»•i Ä‘á»ƒ cÃ³ log/audit trail. */
        if (!identity_b64_equal(current_id, identity_pk)) {
            cJSON_Delete(root);
            clients_send(idx,
                "{\"type\":\"error\",\"msg\":\"Identity change requires rotate_identity\"}");
            return;
        }
    } else {
        /* Account má»›i chÆ°a cÃ³ identity log: ghi leaf initial Ä‘á»ƒ auditor cÃ³ dá»¯
         * liá»‡u dá»±ng Merkle tree vÃ  client khÃ¡c verify bundle. */
        char leaf_hash[65] = {0};
        key_append_identity_log(
            my_uid, 0, identity_pk,
            "", "primary device", "initial",
            leaf_hash, sizeof(leaf_hash));
    }

    if (!key_pqxdh_upload_bundle(my_uid, identity_pk, curve_spk_id, curve_spk,
                              curve_spk_sig, pq_spk_id, pq_alg, pq_spk,
                              pq_spk_sig)) {
        cJSON_Delete(root);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to upload PQXDH bundle\"}");
        return;
    }

    int curve_inserted = 0;
    int pq_inserted = 0;
    cJSON *curve_arr = cJSON_GetObjectItemCaseSensitive(root, "curve_one_time_prekeys");
    if (cJSON_IsArray(curve_arr)) {
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, curve_arr) {
            int kid = json_int(item, "key_id", 0);
            const char *pk = json_str(item, "public_key");
            const char *sig = json_str(item, "signature");
            if (kid > 0 && pk[0] && sig[0] &&
                key_pqxdh_upload_curve_otk(my_uid, kid, pk, sig))
                curve_inserted++;
        }
    }
    cJSON *pq_arr = cJSON_GetObjectItemCaseSensitive(root, "pq_one_time_prekeys");
    if (cJSON_IsArray(pq_arr)) {
        cJSON *item = NULL;
        cJSON_ArrayForEach(item, pq_arr) {
            int kid = json_int(item, "key_id", 0);
            const char *alg = json_str(item, "alg");
            const char *pk = json_str(item, "public_key");
            const char *sig = json_str(item, "signature");
            if (kid > 0 && pqxdh_kem_allowed(alg) && pk[0] && sig[0] &&
                key_pqxdh_upload_pq_otk(my_uid, kid, alg, pk, sig))
                pq_inserted++;
        }
    }
    cJSON_Delete(root);

    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"type\":\"ok\",\"msg\":\"PQXDH bundle uploaded\","
             "\"curve_prekeys\":%d,\"pq_prekeys\":%d}",
             curve_inserted, pq_inserted);
    clients_send(idx, resp);
    log_info("keys: uid=%d uploaded PQXDH bundle (%d curve, %d pq OTKs)",
             my_uid, curve_inserted, pq_inserted);
}

/* â”€â”€ get_pqxdh_bundle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

static void handle_get_pqxdh_bundle(int idx, const char *buf)
{
    /* Láº¥y bundle cá»§a peer vÃ  atomically consume one-time prekey náº¿u cÃ²n. Náº¿u
     * pool háº¿t, repo sáº½ fallback signed prekey theo policy hiện tại. */
    int target_uid = 0;
    jget_int(buf, "user_id", &target_uid);
    if (target_uid <= 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid user_id\"}");
        return;
    }

    PqxdhBundleRecord b;
    if (!key_pqxdh_get_bundle_consuming(target_uid, &b)) {
        char resp[128];
        snprintf(resp, sizeof(resp),
                 "{\"type\":\"error\",\"msg\":\"No PQXDH bundle found\","
                 "\"user_id\":%d}",
                 target_uid);
        clients_send(idx, resp);
        return;
    }
    int identity_version = key_get_identity_version(target_uid);

    size_t resp_sz = strlen(b.identity_pk) + strlen(b.curve_spk) +
        strlen(b.curve_spk_sig) + strlen(b.pq_kem_alg) + strlen(b.pq_spk) +
        strlen(b.pq_spk_sig) + strlen(b.curve_otk) + strlen(b.curve_otk_sig) +
        strlen(b.pq_otk_alg) + strlen(b.pq_otk) + strlen(b.pq_otk_sig) + 1024;
    char *resp = (char *)malloc(resp_sz);
    if (!resp) return;
    snprintf(resp, resp_sz,
             "{\"type\":\"pqxdh_bundle\",\"user_id\":%d,\"version\":2,"
             "\"identity_version\":%d,"
             "\"identity_pk\":\"%s\","
             "\"curve_spk_id\":%d,\"curve_spk\":\"%s\",\"curve_spk_sig\":\"%s\","
             "\"pq_spk_id\":%d,\"pq_kem_alg\":\"%s\",\"pq_spk\":\"%s\",\"pq_spk_sig\":\"%s\","
             "\"curve_otk_id\":%d,\"curve_otk\":\"%s\",\"curve_otk_sig\":\"%s\","
             "\"pq_otk_id\":%d,\"pq_otk_alg\":\"%s\",\"pq_otk\":\"%s\",\"pq_otk_sig\":\"%s\","
             "\"curve_pool_size\":%d,\"pq_pool_size\":%d}",
             target_uid, identity_version >= 0 ? identity_version : 0, b.identity_pk,
             b.curve_spk_id, b.curve_spk, b.curve_spk_sig,
             b.pq_spk_id, b.pq_kem_alg, b.pq_spk, b.pq_spk_sig,
             b.curve_otk_id, b.curve_otk, b.curve_otk_sig,
             b.pq_otk_id, b.pq_otk_alg, b.pq_otk, b.pq_otk_sig,
             b.curve_pool, b.pq_pool);
    clients_send(idx, resp);
    free(resp);
}

/* â”€â”€ dispatcher â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */

int keys_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "upload_keys") == 0) {
        handle_upload_keys(idx, buf);
        return 1;
    }
    if (strcmp(type, "get_my_keys") == 0) {
        handle_get_my_keys(idx);
        return 1;
    }
    if (strcmp(type, "get_my_pqxdh_status") == 0) {
        handle_get_my_pqxdh_status(idx);
        return 1;
    }
    if (strcmp(type, "rotate_identity") == 0) {
        handle_rotate_identity(idx, buf);
        return 1;
    }
    if (strcmp(type, "upload_mls_key_packages") == 0) {
        handle_upload_mls_key_packages(idx, buf);
        return 1;
    }
    if (strcmp(type, "claim_mls_key_package") == 0) {
        handle_claim_mls_key_package(idx, buf);
        return 1;
    }
    if (strcmp(type, "upload_pqxdh_bundle") == 0) {
        handle_upload_pqxdh_bundle(idx, buf);
        return 1;
    }
    if (strcmp(type, "get_pqxdh_bundle") == 0) {
        handle_get_pqxdh_bundle(idx, buf);
        return 1;
    }
    return 0;
}
