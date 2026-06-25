#ifndef SERVICES_PRESENCE_H
#define SERVICES_PRESENCE_H

/* Called when a user logs in — broadcasts their online status to accepted friends.
 * privacy controls: if privacy_online = 'nobody', no broadcast is sent. */
void presence_broadcast_online(int uid);

/* Called when a connection closes — sets status to offline and broadcasts
 * last_seen to friends who are allowed to see it. */
void presence_broadcast_offline(int uid);

/* Dispatch presence-related message types (privacy settings).
 * Returns 1 if handled, 0 if unknown. */
int presence_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_PRESENCE_H */
