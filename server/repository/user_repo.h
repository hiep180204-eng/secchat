#ifndef REPOSITORY_USER_REPO_H
#define REPOSITORY_USER_REPO_H

#include <stddef.h>

/* ── Data types ───────────────────────────────────────────────────────────── */

typedef struct {
    int  id;
    char username[65];
    char email[201];
    char display_name[101];
    char status[16];   /* 'online' | 'offline' | 'away' */
    char last_seen[24];
} UserRecord;

/* ── Write operations ─────────────────────────────────────────────────────── */

/* Insert a new user.  stored_hash is the PBKDF2 hash already computed by
 * the service layer ("salt_hex:derived_hex").
 * Returns 1 on success, 0 if username/email already taken or DB error. */
int user_repo_create(const char *username, const char *email,
                     const char *stored_hash);

/* Update display_name and bio.  Either field may be empty ("").
 * Returns 1 on success, 0 on failure. */
int user_repo_update_profile(int uid,
                             const char *display_name, const char *bio);

/* Store / replace avatar bytes.  mime is e.g. "image/jpeg".
 * Returns 1 on success, 0 on failure. */
int user_repo_set_avatar(int uid,
                         const unsigned char *data, size_t len,
                         const char *mime);

/* Clear avatar columns to NULL.  Returns 1 on success. */
int user_repo_remove_avatar(int uid);

/* Set status to 'online' / 'offline' / 'away'.
 * Returns 1 on success, 0 on failure. */
int user_repo_set_status(int uid, const char *status);

/* ── Read operations ──────────────────────────────────────────────────────── */

/* Find a user by login (tries email first, then username).
 * On success: fills *out_uid, out_username[uname_len], out_hash[hash_len]
 * (stored PBKDF2 hash "salt_hex:derived_hex").
 * Returns 1 on success, 0 if not found. */
int user_repo_find_for_auth(const char *login,
                             int *out_uid,
                             char *out_username, int uname_len,
                             char *out_hash,     int hash_len);

/* Fill *out with basic user fields.
 * Returns 1 on success, 0 if not found. */
int user_repo_find_by_id(int uid, UserRecord *out);

/* Search by username prefix (LIKE %query%), excluding exclude_uid.
 * Fills out[0..max-1].  Returns count of results (0..max). */
int user_repo_search(const char *query, int exclude_uid,
                     UserRecord *out, int max);

/* Fetch profile fields (display_name, bio, avatar presence) for the
 * given uid. The JSON response is assembled by the service layer; this
 * function fills individual output buffers.
 * bio_buf/bio_len: caller supplies a buffer for the bio text.
 * has_avatar is set to 1 if an avatar row exists.
 * Returns 1 on success, 0 if not found. */
int user_repo_get_profile(int uid,
                          char *out_username,     int uname_len,
                          char *out_display_name, int dn_len,
                          char *out_bio,          int bio_len,
                          char *out_status,       int status_len,
                          char *out_last_seen,    int last_seen_len,
                          int  *has_avatar);

/* Read raw avatar bytes for uid into a newly malloc'd buffer.
 * Fills *out_mime (mime[64]).  Caller must free() the returned pointer.
 * Returns pointer on success, NULL if no avatar or on error. */
unsigned char *user_repo_get_avatar(int uid, size_t *out_len, char *out_mime);

/* ── Privacy settings ─────────────────────────────────────────────────────── */

/* Fetch privacy columns for uid.
 * Each buffer receives 'everyone' | 'friends' | 'nobody' (or empty on error).
 * Returns 1 on success, 0 if not found.  Callers should pre-fill defaults. */
int user_repo_get_privacy(int uid,
                          char *out_online,       int online_len,
                          char *out_last_seen,    int ls_len);

/* Update one or more privacy columns.  Pass "" for any field to skip it.
 * Values must be 'everyone', 'friends', or 'nobody'.
 * Returns 1 on success (or when nothing changed), 0 on DB error. */
int user_repo_update_privacy(int uid,
                              const char *online,
                              const char *last_seen);

/* ── Password management ──────────────────────────────────────────────────── */

/* Fetch the stored PBKDF2 hash ("salt_hex:derived_hex") for uid.
 * Fills out_hash[hash_len].  Returns 1 on success, 0 if not found. */
int user_repo_find_hash_by_id(int uid, char *out_hash, int hash_len);

/* Replace the stored password hash for uid.
 * stored_hash must be "salt_hex:derived_hex".
 * Returns 1 on success, 0 on failure. */
int user_repo_update_password(int uid, const char *stored_hash);

#endif /* REPOSITORY_USER_REPO_H */
