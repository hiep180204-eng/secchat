#ifndef REPOSITORY_CONVERSATION_REPO_H
#define REPOSITORY_CONVERSATION_REPO_H

#include <stddef.h>   /* size_t */

/* ── Write operations ─────────────────────────────────────────────────────── */

/* Find or create a direct conversation between two users.
 * Returns conv_id > 0 on success, -1 on error. */
long long conv_find_or_create_dm(int user1_id, int user2_id);

/* Create a group conversation.  Returns conv_id > 0 on success, -1 on error. */
long long conv_create_group(const char *name, int creator_id);

/* Add a user to a conversation.  Silently ignores duplicate (INSERT IGNORE).
 * Returns 1 on success, 0 on error. */
int conv_add_member(long long conv_id, int user_id);

/* Clear hidden_at for all members of a conversation (message received).
 * Returns 1 on success. */
int conv_reset_hidden(long long conv_id);

/* Update last_message_at to NOW().  Returns 1 on success. */
int conv_touch(long long conv_id);

/* ── Read operations ──────────────────────────────────────────────────────── */

/* Returns 1 if uid is a member of conv_id, 0 otherwise. */
int conv_is_member(long long conv_id, int uid);

/* Returns 1 if the conversation has is_disbanded = 1, 0 otherwise. */
int conv_is_disbanded(long long conv_id);

/* Fill uids[0..max-1] with member user_ids.  Returns count. */
int conv_get_members(long long conv_id, int *uids, int max);

/* Remove a member from a conversation (leave / kick).
 * Returns 1 on success, 0 otherwise. */
int conv_remove_member(long long conv_id, int uid);

/* Fill uids[0..max-1] with the other participant's user_id for each DM
 * conversation that uid is a member of.
 * Returns count (0..max). */
int conv_get_dm_partners(int uid, int *uids, int max);

/* Group info helpers */

/* Build a JSON array string "[uid1,uid2,...]" of all member user_ids.
 * out is NUL-terminated; at minimum set to "[]" on error. */
void conv_get_member_ids_json(long long conv_id, char *out, size_t out_sz);

/* Build a canonical JSON array of members with roles:
 * [{"user_id":1,"role":"admin"}, ...].
 * The array is ordered by user_id so clients can sign and hash it
 * deterministically for group commit transcripts. */
void conv_get_members_roles_json(long long conv_id, char *out, size_t out_sz);

/* Update group name/description/avatar (any field may be NULL/empty to skip).
 * avatar_data/avatar_len/avatar_mime are used only when avatar_data != NULL.
 * Returns 1 on success, 0 on error. */
int conv_update_info(long long conv_id,
                     const char *name,
                     const char *description,
                     const unsigned char *avatar_data, size_t avatar_len,
                     const char *avatar_mime);

/* Build a full group_info JSON response and write it into out[out_sz].
 * Includes metadata (name, description, creator_id, is_disbanded) and a
 * members array with roles.
 * Returns 1 on success, 0 if group not found. */
int conv_get_group_info_json(long long conv_id, char *out, size_t out_sz);

/* Group roles */

/* Upsert role for a member in group_roles.  role must be "admin" or "member".
 * Returns 1 on success, 0 otherwise. */
int conv_role_set(long long conv_id, int uid, const char *role);

/* Delete the group_roles row for a member (used on leave / kick).
 * Returns 1 on success. */
int conv_role_delete(long long conv_id, int uid);

/* Returns 1 if uid has role='admin' in group_roles, 0 otherwise. */
int conv_is_admin(long long conv_id, int uid);

#endif /* REPOSITORY_CONVERSATION_REPO_H */
