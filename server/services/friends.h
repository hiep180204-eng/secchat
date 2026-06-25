#ifndef SERVICES_FRIENDS_H
#define SERVICES_FRIENDS_H

/* Dispatch friend/social-graph message types.
 * Returns 1 if the type was handled by this service, 0 if unknown.
 * Caller must have already verified authentication before calling. */
int friends_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_FRIENDS_H */
