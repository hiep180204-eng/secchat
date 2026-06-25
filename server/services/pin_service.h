#ifndef SERVICES_PIN_SERVICE_H
#define SERVICES_PIN_SERVICE_H

/* Handles: pin_message, unpin_message, get_pinned_messages */
int pin_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_PIN_SERVICE_H */
