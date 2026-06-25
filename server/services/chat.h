#ifndef SERVICES_CHAT_H
#define SERVICES_CHAT_H

/*
 * services/chat.h — messaging bounded context
 *
 * chat_dispatch() handles:
 *   message             — send an E2EE message
 *   history             — fetch conversation history
 *   get_inbox           — fetch inbox with last-message previews
 *   start_dm            — open a DM with a friend
 *   edit_message        — edit own message body, broadcast update
 *   delete_message      — soft-delete own message, broadcast update
 *   typing_start        — ephemeral "user is typing" broadcast
 *   typing_stop         — ephemeral "user stopped typing" broadcast
 *   mark_read           — update own unread state without broadcasting read receipts
 *   add_reaction        — add emoji reaction to a message
 *   remove_reaction     — remove own emoji reaction
 *
 * Returns 1 if the type was handled, 0 if not recognised (to continue
 * dispatch chain).
 */
int chat_dispatch(int idx, const char *type, const char *buf);

#endif /* SERVICES_CHAT_H */
