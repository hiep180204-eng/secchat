/*
 * services/profile.c — hồ sơ người dùng: xem/cập nhật display name, bio, avatar
 * và thiết lập quyền riêng tư. Avatar được kiểm magic byte để chặn file giả MIME.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "clients.h"
#include "json_helpers.h"
#include "log.h"
#include "metrics.h"
#include "profile.h"
#include "user_repo.h"
#include "friendship_repo.h"
#include "validation.h"

#define MAX_AVATAR_B64   (128 * 1024)
#define MAX_AVATAR_BYTES (96 * 1024)

/* ── helpers ─────────────────────────────────────────────────────────────── */

/* Validate image magic bytes against MIME type.
   Mirrors the check in db.c (is_valid_image) so we don't depend on db.c. */
static int valid_image(const unsigned char *data, size_t len, const char *mime)
{
    if (!data || len < 4) return 0;
    if (strncmp(mime, "image/jpeg", 10) == 0)
        return data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF;
    if (strncmp(mime, "image/png", 9) == 0)
        return len >= 8 &&
               data[0] == 0x89 && data[1] == 0x50 &&
               data[2] == 0x4E && data[3] == 0x47;
    if (strncmp(mime, "image/gif", 9) == 0)
        return data[0] == 0x47 && data[1] == 0x49 &&
               data[2] == 0x46 && data[3] == 0x38;
    if (strncmp(mime, "image/webp", 10) == 0)
        return len >= 12 &&
               data[0] == 0x52 && data[1] == 0x49 &&
               data[2] == 0x46 && data[3] == 0x46 &&
               data[8] == 0x57 && data[9] == 0x45 &&
               data[10] == 0x42 && data[11] == 0x50;
    return 0;
}

static void notify_profile_updated(int uid)
{
    FriendRecord friends[200];
    int n = friendship_list_for_user(uid, friends, 200);
    char notif[128];
    snprintf(notif, sizeof(notif),
             "{\"type\":\"profile_updated\",\"user_id\":%d}", uid);
    for (int i = 0; i < n; i++)
        clients_send_to_uid(friends[i].id, notif);
}

/* ── handlers ────────────────────────────────────────────────────────────── */

static void handle_get_profile(int idx, const char *buf)
{
    int my_uid     = clients_get_uid(idx);
    int target_uid = 0;
    jget_int(buf, "user_id", &target_uid);
    if (target_uid <= 0) target_uid = my_uid;  /* 0 = own profile */
    int is_own = (target_uid == my_uid);

    /* Profiles and avatars are visible to authenticated users. Group members
     * often need to recognize each other before becoming direct friends, so
     * the old friend-only profile restriction caused noisy errors in groups. */

    char username[65]     = {0};
    char display_name[101]= {0};
    char bio[4096]        = {0};
    char status[16]       = {0};
    char last_seen[24]    = {0};
    char avatar_mime[64]  = {0};
    int  has_avatar       = 0;

    if (!user_repo_get_profile(target_uid,
                               username,     sizeof(username),
                               display_name, sizeof(display_name),
                               bio,          sizeof(bio),
                               status,       sizeof(status),
                               last_seen,    sizeof(last_seen),
                               &has_avatar)) {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"User not found\"}");
        return;
    }
    if (!is_own) {
        char privacy_online[16] = "everyone";
        char privacy_last_seen[16] = "everyone";
        user_repo_get_privacy(target_uid,
                              privacy_online, sizeof(privacy_online),
                              privacy_last_seen, sizeof(privacy_last_seen));
        if (strcmp(privacy_online, "nobody") == 0)
            strncpy(status, "offline", sizeof(status) - 1);
        if (strcmp(privacy_last_seen, "nobody") == 0)
            last_seen[0] = '\0';
    }

    /* JSON-escape bio (may contain any character) */
    size_t bio_esc_sz = strlen(bio) * 2 + 4;
    char  *bio_esc    = (char *)malloc(bio_esc_sz);
    char   dn_esc[210], un_esc[130];
    if (!bio_esc) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}"); return; }

    json_esc(bio,          bio_esc, (int)bio_esc_sz);
    json_esc(display_name, dn_esc,  sizeof(dn_esc));
    json_esc(username,     un_esc,  sizeof(un_esc));

    char *avatar_b64 = NULL;
    if (has_avatar) {
        size_t avatar_len = 0;
        unsigned char *avatar_raw = user_repo_get_avatar(
            target_uid, &avatar_len, avatar_mime);
        if (avatar_raw && avatar_len > 0) {
            size_t b64_cap = 4 * ((avatar_len + 2) / 3) + 1;
            avatar_b64 = (char *)calloc(b64_cap, 1);
            if (avatar_b64) {
                int n = EVP_EncodeBlock(
                    (unsigned char *)avatar_b64, avatar_raw, (int)avatar_len);
                if (n < 0) {
                    free(avatar_b64);
                    avatar_b64 = NULL;
                }
            }
        }
        if (avatar_raw) free(avatar_raw);
    }

    size_t resp_sz = strlen(bio_esc) + (avatar_b64 ? strlen(avatar_b64) : 0) + 768;
    char  *resp    = (char *)malloc(resp_sz);
    if (!resp) {
        free(avatar_b64);
        free(bio_esc);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }

    snprintf(resp, resp_sz,
             "{\"type\":\"profile\","
             "\"user_id\":%d,"
             "\"username\":\"%s\","
             "\"display_name\":\"%s\","
             "\"bio\":\"%s\","
             "\"status\":\"%s\","
             "\"last_seen\":\"%s\","
             "\"has_avatar\":%s,"
             "\"avatar_b64\":\"%s\","
             "\"avatar_mime\":\"%s\","
             "\"is_own\":%s}",
             target_uid, un_esc, dn_esc, bio_esc, status, last_seen,
             has_avatar ? "true" : "false",
             avatar_b64 ? avatar_b64 : "",
             avatar_b64 ? avatar_mime : "",
             is_own     ? "true" : "false");
    clients_send(idx, resp);
    free(avatar_b64);
    free(bio_esc);
    free(resp);
}

static void handle_update_profile(int idx, const char *buf)
{
    int my_uid = clients_get_uid(idx);
    size_t buf_len = strlen(buf);

    char *display_name = (char *)calloc(buf_len + 1, 1);
    char *bio          = (char *)calloc(buf_len + 1, 1);
    if (!display_name || !bio) {
        free(display_name); free(bio);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    jget(buf, "display_name", display_name, (int)(buf_len + 1));
    jget(buf, "bio",          bio,          (int)(buf_len + 1));

    if (!domain_validate_display_name(display_name)) {
        metrics_validation_error();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Display name too long (max 64 chars)\"}");
        free(display_name); free(bio);
        return;
    }
    if (!domain_validate_bio(bio)) {
        metrics_validation_error();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Bio too long (max 512 chars)\"}");
        free(display_name); free(bio);
        return;
    }

    if (user_repo_update_profile(my_uid, display_name, bio)) {
        clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Profile updated\"}");
        notify_profile_updated(my_uid);
    } else {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to update profile\"}");
    }

    free(display_name);
    free(bio);
}

static void handle_upload_avatar(int idx, const char *buf)
{
    int    my_uid  = clients_get_uid(idx);
    size_t buf_len = strlen(buf);

    char *b64 = (char *)calloc(buf_len + 1, 1);
    char  mime[64] = {0};
    if (!b64) { clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}"); return; }

    jget(buf, "data", b64, (int)(buf_len + 1));
    jget(buf, "mime", mime, sizeof(mime));

    if (!b64[0]) {
        free(b64);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"No avatar data\"}");
        return;
    }

    /* Base64-decode via OpenSSL BIO */
    size_t b64_len = strlen(b64);
    if (b64_len > MAX_AVATAR_B64) {
        free(b64);
        metrics_validation_error();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Avatar too large\"}");
        return;
    }
    unsigned char *raw = (unsigned char *)malloc(b64_len);
    if (!raw) { free(b64); clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}"); return; }

    BIO *bmem = BIO_new_mem_buf(b64, (int)b64_len);
    BIO *b64f = BIO_new(BIO_f_base64());
    if (!bmem || !b64f) {
        if (bmem) BIO_free(bmem);
        if (b64f) BIO_free(b64f);
        free(raw);
        free(b64);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Server error\"}");
        return;
    }
    BIO_set_flags(b64f, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_push(b64f, bmem);
    int decoded = BIO_read(bmem, raw, (int)b64_len);
    BIO_free_all(bmem);
    free(b64);

    if (decoded <= 0) {
        free(raw);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid base64\"}");
        return;
    }
    if ((size_t)decoded > MAX_AVATAR_BYTES) {
        free(raw);
        metrics_validation_error();
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Avatar too large\"}");
        return;
    }

    const char *used_mime = mime[0] ? mime : "image/jpeg";
    if (!valid_image(raw, (size_t)decoded, used_mime)) {
        free(raw);
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Invalid image format\"}");
        return;
    }

    if (user_repo_set_avatar(my_uid, raw, (size_t)decoded, used_mime)) {
        clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Avatar uploaded\"}");
        notify_profile_updated(my_uid);
    } else {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to upload avatar\"}");
    }

    free(raw);
}

static void handle_remove_avatar(int idx)
{
    int my_uid = clients_get_uid(idx);
    if (user_repo_remove_avatar(my_uid)) {
        clients_send(idx, "{\"type\":\"ok\",\"msg\":\"Avatar removed\"}");
        notify_profile_updated(my_uid);
    } else {
        clients_send(idx, "{\"type\":\"error\",\"msg\":\"Failed to remove avatar\"}");
    }
}

/* ── dispatcher ──────────────────────────────────────────────────────────── */

int profile_dispatch(int idx, const char *type, const char *buf)
{
    if (strcmp(type, "get_profile") == 0) {
        handle_get_profile(idx, buf);
        return 1;
    }
    if (strcmp(type, "update_profile") == 0) {
        handle_update_profile(idx, buf);
        return 1;
    }
    if (strcmp(type, "upload_avatar") == 0) {
        handle_upload_avatar(idx, buf);
        return 1;
    }
    if (strcmp(type, "remove_avatar") == 0) {
        handle_remove_avatar(idx);
        return 1;
    }
    return 0;
}
