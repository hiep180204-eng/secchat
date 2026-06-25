#ifndef REPOSITORY_FRIENDSHIP_REPO_H
#define REPOSITORY_FRIENDSHIP_REPO_H

/* ── Data types ───────────────────────────────────────────────────────────── */

typedef struct {
    int  id;
    char username[65];
    char display_name[101];
    char status[16];   /* 'online' | 'offline' | 'away' */
    char last_seen[24];
} FriendRecord;

typedef struct {
    long long request_id;
    int       user_id;
    char      username[65];
    char      display_name[101];
    char      requested_at[24];
} FriendRequestRecord;

/* ── Write operations ─────────────────────────────────────────────────────── */

/* Insert a 'pending' friendship row.  Canonical row: user_id < friend_id.
 * Returns 1 on success, 0 if the row already exists or DB error. */
int friendship_create_pending(int user_id, int friend_id, int requester_id);

/* Mark a pending friendship as 'accepted'.
 * The requester_uid identifies which direction was the original request.
 * Returns 1 if a row was updated, 0 otherwise. */
int friendship_accept(int my_uid, int requester_uid);

/* Delete any friendship row between uid_a and uid_b (either direction).
 * Returns 1 (idempotent — does not fail if absent). */
int friendship_delete(int uid_a, int uid_b);

/* ── Read operations ──────────────────────────────────────────────────────── */

/* Fill out[0..max-1] with accepted friends of uid.
 * Returns count (0..max). */
int friendship_list_for_user(int uid, FriendRecord *out, int max);

/* Fill out[0..max-1] with pending inbound requests for uid.
 * Returns count (0..max). */
int friendship_list_pending(int uid, FriendRequestRecord *out, int max);

/* Returns 1 if uid_a and uid_b have an accepted friendship, 0 otherwise. */
int friendship_exists_accepted(int uid_a, int uid_b);

/* Fetch status/requester for an existing row. Returns 1 if found. */
int friendship_get_status(int uid_a, int uid_b,
                          char *status, int status_len,
                          int *requester_id);

#endif /* REPOSITORY_FRIENDSHIP_REPO_H */
