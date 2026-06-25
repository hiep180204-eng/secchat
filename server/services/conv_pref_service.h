#ifndef SERVICES_CONV_PREF_SERVICE_H
#define SERVICES_CONV_PREF_SERVICE_H

/* Handles: mute_conversation, archive_conversation,
 *          pin_conversation, mark_unread, mark_read */
int conv_pref_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_CONV_PREF_SERVICE_H */
