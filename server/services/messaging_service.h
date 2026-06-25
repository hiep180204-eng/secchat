#ifndef SERVICES_MESSAGING_SERVICE_H
#define SERVICES_MESSAGING_SERVICE_H

/* Handles: message, history, get_inbox, start_dm,
 *          edit_message, delete_message,
 *          typing_start, typing_stop */
int messaging_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_MESSAGING_SERVICE_H */
