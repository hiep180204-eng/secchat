#ifndef REPOSITORY_BLOCK_REPO_H
#define REPOSITORY_BLOCK_REPO_H

/* block_create: blocker blocks blocked_id.  Returns 1 on success. */
int block_create(int blocker_id, int blocked_id);

/* block_delete: removes a block.  Returns 1 on success. */
int block_delete(int blocker_id, int blocked_id);

/* block_exists: 1 if blocker_id has blocked blocked_id. */
int block_exists(int blocker_id, int blocked_id);

/* block_either: 1 if uid1 blocked uid2 OR uid2 blocked uid1. */
int block_either(int uid1, int uid2);

/* block_list_for_user: fills out_ids[] with UIDs that uid has blocked.
 * Returns count (0..max). */
int block_list_for_user(int uid, int *out_ids, int max);

#endif /* REPOSITORY_BLOCK_REPO_H */
