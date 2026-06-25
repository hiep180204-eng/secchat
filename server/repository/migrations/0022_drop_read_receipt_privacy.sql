-- SecChat no longer supports read receipts.  Conversation unread state remains
-- local to each user through conversation_members.last_read_at/force_unread.
ALTER TABLE users DROP COLUMN privacy_read_receipt;
