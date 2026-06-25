#ifndef DOMAIN_CALLER_CONTEXT_H
#define DOMAIN_CALLER_CONTEXT_H

/*
 * domain/caller_context.h — The authenticated caller abstraction.
 *
 * CallerContext replaces the raw "int idx" pattern that currently appears
 * in every service handler.  Instead of:
 *
 *   static void handle_foo(int idx, const char *buf) {
 *       int uid = clients_get_uid(idx);
 *       char uname[USERNAME_LEN]; clients_get_username(idx, uname);
 *       ...
 *   }
 *
 * services can be written as:
 *
 *   static void handle_foo(CallerContext caller, const char *buf) {
 *       // caller.uid, caller.username, caller.idx are pre-populated
 *       ...
 *   }
 *
 * This makes handler signatures self-documenting, eliminates boilerplate,
 * and allows service logic to be unit-tested with a synthetic CallerContext
 * (no live slot needed).
 *
 * NOTE: caller_from_slot() is defined in caller_context.c which depends on
 * clients.h.  The struct definition here is intentionally transport-free.
 */

#define CALLER_USERNAME_MAX 64   /* matches clients.h USERNAME_LEN */

typedef struct {
    int  uid;                          /* authenticated user id  (> 0) */
    char username[CALLER_USERNAME_MAX];/* username snapshot at call time */
    int  idx;                          /* slot index for sending responses */
} CallerContext;

/* Convenience: returns 1 when the caller is authenticated (uid > 0). */
static inline int caller_ok(const CallerContext *c) { return c->uid > 0; }

/* Build a synthetic CallerContext for unit tests (no live slot).
 * idx is set to -1 (no real socket). */
static inline CallerContext caller_synthetic(int uid, const char *username)
{
    CallerContext c;
    int i;
    c.uid = uid;
    c.idx = -1;
    for (i = 0; i < CALLER_USERNAME_MAX - 1 && username[i]; i++)
        c.username[i] = username[i];
    c.username[i] = '\0';
    return c;
}

#endif /* DOMAIN_CALLER_CONTEXT_H */
