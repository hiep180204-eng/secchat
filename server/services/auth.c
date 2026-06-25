/*
 * services/auth.c — đăng ký, đăng nhập, đổi mật khẩu.
 *
 * Server chỉ thao tác trên password-hash do client gửi (đã PBKDF2 phía client),
 * rồi băm lại bằng PBKDF2 600k vòng + salt ngẫu nhiên trước khi lưu — không bao
 * giờ thấy mật khẩu gốc. Có rate limit theo (login, ip) để chống brute-force.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <pthread.h>
#endif

#include <openssl/sha.h>

#include "log.h"
#include "clients.h"
#include "json_helpers.h"
#include "metrics.h"
#include "auth.h"
#include "crypto.h"
#include "user_repo.h"
#include "presence.h"
#include "notifications.h"
#include "validation.h"

/* Server-side PBKDF2 parameters (must match db.c for existing hashes). */
#define PBKDF2_ITERATIONS 600000
#define SALT_LEN          16
#define DERIVED_LEN       32

/* ── S3: Hardened Auth Rate Limiter ──────────────────────────────────────
 *
 * Key improvements over the original implementation:
 *   • Open-addressing hashmap (O(1) average) vs linear O(n) scan
 *   • Composite key: SHA-256(login || ':' || ip) — prevents one IP from
 *     brute-forcing multiple accounts under the IP-only limit
 *   • TTL eviction: slots inactive > RATE_TTL_SECS are reclaimed
 *   • Fail-closed: table-full rejects the attempt instead of allowing it
 *   • Metric counter g_rate_full tracks table-full events
 */

#define RATE_BUCKETS      1024    /* power-of-2 open-addressing hashmap  */
#define RATE_MAX_FAILURES    5    /* max failures per window              */
#define RATE_WINDOW_SECS    30    /* sliding window (seconds)             */
#define RATE_LOCKOUT_SECS  300    /* lockout duration after breach        */
#define RATE_TTL_SECS     3600    /* evict slots inactive > 1 hour        */
#define RATE_COMPACT_AT    768    /* compact table when load >= 75%       */

typedef enum { RATE_EMPTY = 0, RATE_ACTIVE, RATE_TOMB } RateState;

typedef struct {
    char      key[65];       /* SHA-256(login||ip) hex, 64 chars + NUL  */
    RateState state;
    int       failures;
    time_t    first_fail;
    time_t    locked_until;
    time_t    last_update;   /* timestamp of last access — for TTL       */
} RateBucket;

static RateBucket g_rate[RATE_BUCKETS];
static int        g_rate_load = 0;   /* active + tombstone count         */
static uint64_t   g_rate_full = 0;   /* metric: table-full rejections    */

#ifdef _WIN32
static CRITICAL_SECTION g_rate_mtx;
#define RATE_LOCK()   EnterCriticalSection(&g_rate_mtx)
#define RATE_UNLOCK() LeaveCriticalSection(&g_rate_mtx)
#else
static pthread_mutex_t g_rate_mtx = PTHREAD_MUTEX_INITIALIZER;
#define RATE_LOCK()   pthread_mutex_lock(&g_rate_mtx)
#define RATE_UNLOCK() pthread_mutex_unlock(&g_rate_mtx)
#endif

/* Khởi tạo mutex cho bảng rate-limit (chỉ cần trên Windows). */
void auth_init(void)
{
#ifdef _WIN32
    InitializeCriticalSection(&g_rate_mtx);
#endif
}

/* Compute composite key: hex(SHA-256(login + ':' + ip)) */
static void rate_make_key(const char *login, const char *ip, char key[65])
{
    char src[320];
    snprintf(src, sizeof(src), "%s:%s",
             login ? login : "", ip ? ip : "");
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)src, strlen(src), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(key + i * 2, 3, "%02x", digest[i]);
    key[64] = '\0';
}

/* Map 64-char hex key to starting bucket index */
static unsigned int rate_bucket(const char key[65])
{
    /* Parse first 4 hex chars (16 bits) of SHA-256 as bucket index */
    unsigned int h = 0;
    for (int i = 0; i < 4; i++) {
        char c = key[i];
        h = (h << 4) | (unsigned int)((c >= 'a') ? c - 'a' + 10 : c - '0');
    }
    return h % RATE_BUCKETS;
}

/* Rebuild the hashmap, evicting all expired entries.
 * Caller must hold RATE_LOCK(). */
static void rate_compact(time_t now)
{
    RateBucket live[RATE_BUCKETS];
    int n = 0;
    for (int i = 0; i < RATE_BUCKETS; i++) {
        if (g_rate[i].state == RATE_ACTIVE &&
            now - g_rate[i].last_update <= RATE_TTL_SECS)
            live[n++] = g_rate[i];
    }
    memset(g_rate, 0, sizeof(g_rate));
    g_rate_load = 0;
    for (int i = 0; i < n; i++) {
        unsigned int start = rate_bucket(live[i].key);
        for (int j = 0; j < RATE_BUCKETS; j++) {
            int s = (int)((start + (unsigned int)j) % RATE_BUCKETS);
            if (g_rate[s].state == RATE_EMPTY) {
                g_rate[s] = live[i];
                g_rate_load++;
                break;
            }
        }
    }
    log_info("Rate-limit table compacted: %d live entries", n);
}

/* Trả 1 nếu (login, ip) còn được phép thử đăng nhập, 0 nếu đang bị khóa tạm.
 * record_failure=1 để ghi nhận một lần thử SAI.
 *
 * IP rỗng/không xác định → fail-closed (từ chối) cho an toàn. */
int rate_check(const char *login, const char *ip, int record_failure)
{
    if (!ip || !ip[0]) {
        /* No IP info — fail-closed: cannot rate-limit without a key */
        return 0;
    }
    time_t now = time(NULL);
    RATE_LOCK();

    if (g_rate_load >= RATE_COMPACT_AT)
        rate_compact(now);

    char key[65];
    rate_make_key(login, ip, key);
    unsigned int start = rate_bucket(key);
    int first_tomb = -1;
    RateBucket *b  = NULL;

    for (int i = 0; i < RATE_BUCKETS; i++) {
        int slot = (int)((start + (unsigned int)i) % RATE_BUCKETS);
        RateBucket *s = &g_rate[slot];

        if (s->state == RATE_EMPTY) {
            /* Key is not in the table */
            if (!record_failure) { RATE_UNLOCK(); return 1; }
            /* Allocate slot (prefer first tombstone to avoid load growth) */
            int alloc = (first_tomb >= 0) ? first_tomb : slot;
            if (g_rate[alloc].state == RATE_EMPTY) g_rate_load++;
            memset(&g_rate[alloc], 0, sizeof(g_rate[alloc]));
            memcpy(g_rate[alloc].key, key, 64);  /* key is exactly 64 hex chars + NUL */
            g_rate[alloc].key[64] = '\0';
            g_rate[alloc].state = RATE_ACTIVE;
            g_rate[alloc].last_update = now;
            b = &g_rate[alloc];
            break;
        }
        if (s->state == RATE_TOMB) {
            if (first_tomb < 0) first_tomb = slot;
            continue;
        }
        /* RATE_ACTIVE: check TTL */
        if (now - s->last_update > RATE_TTL_SECS) {
            s->state = RATE_TOMB;              /* expire in-place */
            if (first_tomb < 0) first_tomb = slot;
            continue;
        }
        if (strcmp(s->key, key) == 0) { b = s; break; }
    }

    if (!b) {
        /* Table still full after compact — fail-closed */
        g_rate_full++;
        log_warn("Rate-limit table full (load=%d), failing closed (total=%llu)",
                 g_rate_load, (unsigned long long)g_rate_full);
        RATE_UNLOCK();
        return 0;
    }

    /* Check lockout */
    if (b->locked_until > now) { RATE_UNLOCK(); return 0; }

    /* Expire sliding window */
    if (b->first_fail > 0 && now - b->first_fail > RATE_WINDOW_SECS) {
        b->failures = 0; b->first_fail = 0; b->locked_until = 0;
    }

    if (record_failure) {
        if (b->failures == 0) b->first_fail = now;
        b->failures++;
        b->last_update = now;
        if (b->failures >= RATE_MAX_FAILURES) {
            b->locked_until = now + RATE_LOCKOUT_SECS;
            log_warn("Rate-limit: key=%.12s... locked for %ds after %d failures",
                     key, RATE_LOCKOUT_SECS, b->failures);
        }
    }
    RATE_UNLOCK();
    return 1;
}

/* Input validation delegates to domain/validation.h. */

/* These wrappers maintain backward-compatible call sites while ensuring
 * the canonical validation rules live in one place (domain/validation.c). */
static int valid_username(const char *s) { return domain_validate_username(s); }
static int valid_email(const char *s)    { return domain_validate_email(s);    }

/* ── Auth handlers ───────────────────────────────────────────── */

/* Đăng nhập: kiểm rate limit, verify password-hash (băm lại PBKDF2 600k rồi so),
 * đặt online và flush thông báo offline. Sai thì trả lỗi mơ hồ (không lộ là sai
 * email hay sai mật khẩu). */
void handle_auth(int idx, const char *buf)
{
    uint64_t _auth_t0 = metrics_now_us();

    /* S3: Parse credentials first so we can build the composite (login, ip) key.
     * Accept "email" field (new clients) or "username" field (backward compat). */
    char login[200] = {0}, pwhash[128] = {0};
    jget(buf, "email",    login,  sizeof(login));
    if (!login[0])
        jget(buf, "username", login, sizeof(login));
    jget(buf, "password", pwhash, sizeof(pwhash));

    /* Reject (login, ip) combinations that have hit the failure threshold. */
    char ip[IP_LEN] = {0};
    clients_get_ip(idx, ip);
    if (!rate_check(login, ip, 0)) {
        metrics_auth_ratelimited();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Too many failed login attempts — try again later\"}");
        metrics_lat_auth_us(metrics_now_us() - _auth_t0);
        return;
    }

    /* Authenticate via user_repo + local PBKDF2 in the service layer. */
    int  uid            = -1;
    char actual_uname[64] = {0};
    char stored_hash[200] = {0};

    if (!user_repo_find_for_auth(login, &uid, actual_uname, sizeof(actual_uname),
                                 stored_hash, sizeof(stored_hash)) || uid < 0) {
        rate_check(login, ip, 1);
        metrics_auth_fail();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid credentials\"}");
        metrics_lat_auth_us(metrics_now_us() - _auth_t0);
        return;
    }

    /* Verify PBKDF2: stored_hash = "salt_hex:derived_hex" */
    char *colon = strchr(stored_hash, ':');
    if (!colon) {
        rate_check(login, ip, 1);
        metrics_auth_fail();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid credentials\"}");
        metrics_lat_auth_us(metrics_now_us() - _auth_t0);
        return;
    }
    *colon = '\0';
    unsigned char salt[SALT_LEN];
    unsigned char stored_derived[DERIVED_LEN];
    if (hex_decode(stored_hash, salt, SALT_LEN) != SALT_LEN ||
        hex_decode(colon + 1,   stored_derived, DERIVED_LEN) != DERIVED_LEN) {
        rate_check(login, ip, 1);
        metrics_auth_fail();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid credentials\"}");
        metrics_lat_auth_us(metrics_now_us() - _auth_t0);
        return;
    }
    unsigned char check[DERIVED_LEN];
    if (!pbkdf2_sha256(pwhash, salt, SALT_LEN, PBKDF2_ITERATIONS, check, DERIVED_LEN)) {
        rate_check(login, ip, 1);
        metrics_auth_fail();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid credentials\"}");
        metrics_lat_auth_us(metrics_now_us() - _auth_t0);
        return;
    }
    int diff = 0;
    for (int i = 0; i < DERIVED_LEN; i++) diff |= check[i] ^ stored_derived[i];
    if (diff != 0) {
        rate_check(login, ip, 1);
        metrics_auth_fail();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid credentials\"}");
        metrics_lat_auth_us(metrics_now_us() - _auth_t0);
        return;
    }

    /* Mark online */
    user_repo_set_status(uid, "online");

    /* Store identity in this slot, then replace stale sessions for the same
       account. The current E2EE state model is single-session: allowing two
       windows to keep sending would fork Double Ratchet / MLS state. */
    Client *c = clients_slot(idx);
    if (c) {
        c->user_id = uid;
        strncpy(c->username, actual_uname, USERNAME_LEN - 1);
        c->username[USERNAME_LEN - 1] = '\0';   /* L-3 */
    }
    int replaced = clients_replace_other_sessions(uid, idx);
    char resp[256];
    snprintf(resp, sizeof(resp),
        "{\"type\":\"ok\",\"msg\":\"Login successful\",\"user_id\":%d,\"username\":\"%s\"}",
        uid, actual_uname);
    clients_send(idx, resp);
    /* Do not log the login field; it may be an email address. */
    log_info("User '%s' (uid=%d) authenticated", actual_uname, uid);
    if (replaced > 0)
        log_info("User uid=%d replaced %d stale session(s)", uid, replaced);
    metrics_auth_ok();
    metrics_lat_auth_us(metrics_now_us() - _auth_t0);

    /* Broadcast online presence to friends. */
    presence_broadcast_online(uid);

    /* Deliver any offline notifications queued while user was away. */
    notifications_flush(uid, idx);
}

/* Đăng ký tài khoản mới: validate username/email/pwhash, băm lại password (PBKDF2
 * 600k + salt) rồi lưu. */
void handle_register(int idx, const char *buf)
{
    /* Use 130-byte buffer so jget can read up to 129 chars — this lets
       valid_username() detect names exceeding the 63-char cap instead of
       silently truncating them (jget would otherwise cap at 63). */
    char uname[130] = {0}, email[200] = {0}, pwhash[128] = {0};
    jget(buf, "username", uname,  sizeof(uname));
    jget(buf, "email",    email,  sizeof(email));
    jget(buf, "password", pwhash, sizeof(pwhash));

    /* Server-side input validation. */
    if (!valid_username(uname)) {
        clients_send(idx, "{\"type\":\"error\","
                     "\"msg\":\"Username must be 3-63 chars, letters/digits/underscore only\"}");
        return;
    }
    if (!valid_email(email)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid email address\"}");
        return;
    }
    /* Client sends SHA-256 hex (64 chars) as password before server re-hashes */
    if (strlen(pwhash) != 64) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid password format\"}");
        return;
    }

    /* Generate salt + PBKDF2 in the service layer, then persist via user_repo. */
    unsigned char salt[SALT_LEN];
    if (!crypto_random_bytes(salt, SALT_LEN)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    unsigned char derived[DERIVED_LEN];
    if (!pbkdf2_sha256(pwhash, salt, SALT_LEN, PBKDF2_ITERATIONS,
                       derived, DERIVED_LEN)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    char salt_hex[SALT_LEN * 2 + 1];
    char derived_hex[DERIVED_LEN * 2 + 1];
    hex_encode(salt,    SALT_LEN,    salt_hex);
    hex_encode(derived, DERIVED_LEN, derived_hex);
    char stored_hash[200];
    snprintf(stored_hash, sizeof(stored_hash), "%s:%s", salt_hex, derived_hex);

    if (user_repo_create(uname, email, stored_hash)) {
        clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Registration successful\"}");
        /* Omit email from logs; it is PII. */
        log_info("New user registered: '%s'", uname);
        metrics_register_ok();
    } else {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Username or email already taken\"}");
    }
}

/* ── change_password ─────────────────────────────────────────────────────── */

/* Đổi mật khẩu: kiểm hash cũ rồi lưu hash mới. Việc bọc lại local E2EE state
 * bằng master key mới do CLIENT tự làm (server không có master key). */
void handle_change_password(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);

    char old_pw[128] = {0};
    char new_pw[128] = {0};
    jget(buf, "old_password", old_pw, sizeof(old_pw));
    jget(buf, "new_password", new_pw, sizeof(new_pw));

    /* Both must be 64-char SHA-256 hex strings (client pre-hashes) */
    if (strlen(old_pw) != 64 || strlen(new_pw) != 64) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid password format\"}");
        return;
    }

    /* Fetch current stored hash */
    char stored_hash[200] = {0};
    if (!user_repo_find_hash_by_id(my_uid, stored_hash, sizeof(stored_hash))) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"User not found\"}");
        return;
    }

    /* Verify old_pw against stored PBKDF2 hash */
    char *colon = strchr(stored_hash, ':');
    if (!colon) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    *colon = '\0';
    unsigned char salt[SALT_LEN];
    unsigned char stored_derived[DERIVED_LEN];
    if (hex_decode(stored_hash,  salt,           SALT_LEN)    != SALT_LEN ||
        hex_decode(colon + 1,    stored_derived,  DERIVED_LEN) != DERIVED_LEN) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    unsigned char check[DERIVED_LEN];
    if (!pbkdf2_sha256(old_pw, salt, SALT_LEN, PBKDF2_ITERATIONS,
                       check, DERIVED_LEN)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    int diff = 0;
    for (int i = 0; i < DERIVED_LEN; i++) diff |= check[i] ^ stored_derived[i];
    if (diff != 0) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Incorrect current password\"}");
        return;
    }

    /* Hash the new password */
    unsigned char new_salt[SALT_LEN];
    if (!crypto_random_bytes(new_salt, SALT_LEN)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    unsigned char new_derived[DERIVED_LEN];
    if (!pbkdf2_sha256(new_pw, new_salt, SALT_LEN, PBKDF2_ITERATIONS,
                       new_derived, DERIVED_LEN)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    char salt_hex[SALT_LEN * 2 + 1];
    char derived_hex[DERIVED_LEN * 2 + 1];
    hex_encode(new_salt,    SALT_LEN,    salt_hex);
    hex_encode(new_derived, DERIVED_LEN, derived_hex);
    char new_stored[200];
    snprintf(new_stored, sizeof(new_stored), "%s:%s", salt_hex, derived_hex);

    if (user_repo_update_password(my_uid, new_stored)) {
        clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Password changed successfully\"}");
        log_info("auth: uid=%d changed password", my_uid);
    } else {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to update password\"}");
    }
}
