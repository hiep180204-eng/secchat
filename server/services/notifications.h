#ifndef SERVICES_NOTIFICATIONS_H
#define SERVICES_NOTIFICATIONS_H

/*
 * services/notifications.h — offline notification delivery
 *
 * notifications_flush() is called after a user authenticates; it
 * delivers any pending rows from notification_queue and marks them sent.
 */
void notifications_flush(int uid, int client_idx);

#endif /* SERVICES_NOTIFICATIONS_H */
