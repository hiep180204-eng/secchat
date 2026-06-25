-- Store edits as append-only encrypted events.
ALTER TABLE messages
    ADD COLUMN edit_target_message_id BIGINT DEFAULT NULL;

CREATE INDEX idx_messages_edit_target
    ON messages(edit_target_message_id);
