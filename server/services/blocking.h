#ifndef SERVICES_BLOCKING_H
#define SERVICES_BLOCKING_H

/*
 * services/blocking.h - user blocking
 *
 * blocking_dispatch() handles:
 *   block_user         — block another user
 *   unblock_user       — remove a block
 *   get_blocked_list   — list UIDs the caller has blocked
 *
 * Returns 1 if the type was handled, 0 if not recognised.
 */
int blocking_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_BLOCKING_H */
