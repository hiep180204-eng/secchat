#ifndef INFRA_RATELIMIT_H
#define INFRA_RATELIMIT_H

/*
 * infra/ratelimit.h — per-user token-bucket message rate limiter
 *
 * ratelimit_init() — initialise the global table (call once from main).
 * ratelimit_check(uid) — return 1 if the user may send a message now,
 *                        0 if their bucket is empty (throttled).
 */
void ratelimit_init(void);
int  ratelimit_check(int uid);

#endif /* INFRA_RATELIMIT_H */
