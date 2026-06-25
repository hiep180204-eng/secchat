#ifndef SERVICES_AUTH_H
#define SERVICES_AUTH_H

/* Must be called once from main() before accepting connections.
 * On Linux the mutex is statically initialized; on Windows this
 * calls InitializeCriticalSection for g_rate_mtx. */
void auth_init(void);

/* S3: Hardened rate-limiter check.
 * Returns 1 if (login, ip) may attempt auth, 0 if locked out.
 * Pass record_failure=1 to register a failed attempt. */
int rate_check(const char *login, const char *ip, int record_failure);

/* Message handlers — called from dispatch() in main.c */
void handle_auth(int idx, const char *buf);
void handle_register(int idx, const char *buf);
void handle_change_password(int idx, const char *buf);

#endif /* SERVICES_AUTH_H */
