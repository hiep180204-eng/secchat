#ifndef REPOSITORY_MESSAGE_REPO_H
#define REPOSITORY_MESSAGE_REPO_H

#include <stddef.h>

/* ── Write operations ─────────────────────────────────────────────────────── */

/* Insert a message.  Returns message_id > 0 on success, -1 on error. */
long long msg_insert(long long conv_id, int sender_id, const char *body);

/* Insert an encrypted edit event for a previous message. */
long long msg_insert_edit_event(long long conv_id, int sender_id,
                                const char *body, long long target_msg_id);

/* Soft-delete a message (sets deleted_at = NOW(), body stays in DB).
 * Only succeeds if sender_id matches.
 * Returns 1 on success, 0 otherwise. */
int msg_soft_delete(long long msg_id, int sender_id);

/* ── Read operations ──────────────────────────────────────────────────────── */

/* Fetch the conversation_id for a message (for broadcast after edit/delete).
 * Returns conv_id > 0 on success, -1 if not found. */
long long msg_get_conv_id(long long msg_id);

/* Fetch the conversation for an editable message owned by uid. */
long long msg_get_editable_conv_id(long long msg_id, int uid);

#endif /* REPOSITORY_MESSAGE_REPO_H */
