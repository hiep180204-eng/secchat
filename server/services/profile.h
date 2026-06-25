#ifndef SERVICES_PROFILE_H
#define SERVICES_PROFILE_H

/* Dispatch profile-related message types.
 * Returns 1 if the type was handled by this service, 0 if unknown.
 * Caller must have already verified authentication. */
int profile_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_PROFILE_H */
