/*
 * services/notifications.c — gửi thông báo cho người dùng đang offline.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "notifications.h"
#include "clients.h"
#include "log.h"
#include "notification_repo.h"

#define MAX_NOTIFS_PER_FLUSH  100

void notifications_flush(int uid, int client_idx)
{
    if (uid <= 0) return;

    NotifRecord *recs = (NotifRecord *)malloc(
        sizeof(NotifRecord) * MAX_NOTIFS_PER_FLUSH);
    if (!recs) return;

    int n = notif_flush_for_user(uid, recs, MAX_NOTIFS_PER_FLUSH);
    for (int i = 0; i < n; i++) {
        clients_send(client_idx, recs[i].payload);
        notif_mark_sent(recs[i].id);
    }
    if (n > 0)
        log_info("notifications: flushed %d pending notif(s) for uid=%d",
                 n, uid);
    free(recs);
}
