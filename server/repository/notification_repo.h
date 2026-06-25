#ifndef REPOSITORY_NOTIFICATION_REPO_H
#define REPOSITORY_NOTIFICATION_REPO_H

#include <stddef.h>

typedef struct {
    long long id;
    char      type[64];
    char      payload[4096];
} NotifRecord;

/* Enqueue a notification for a user.  Returns 1 on success. */
int notif_enqueue(int user_id, const char *type, const char *payload);

/* Fetch all unsent notifications for user_id (up to max).
 * Fills out[0..n-1], returns n. */
int notif_flush_for_user(int user_id, NotifRecord *out, int max);

/* Mark a single notification row as sent. */
int notif_mark_sent(long long notif_id);

#endif /* REPOSITORY_NOTIFICATION_REPO_H */
