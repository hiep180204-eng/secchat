-- Store the read cursor by message id so unread state is not affected by
-- DATETIME precision differences between conversation_members and messages.

ALTER TABLE conversation_members
    ADD COLUMN last_read_message_id BIGINT NOT NULL DEFAULT 0;

UPDATE conversation_members cm
SET last_read_message_id = COALESCE((
    SELECT MAX(m.id)
    FROM messages m
    JOIN conversations c ON c.id = m.conversation_id
    WHERE m.conversation_id = cm.conversation_id
      AND m.deleted_at IS NULL
      AND m.sent_at < DATE_ADD(cm.last_read_at, INTERVAL 1 SECOND)
      AND (c.type != 'group' OR m.sent_at >= cm.joined_at)
      AND (m.body LIKE 'S3DR:%'
           OR m.body LIKE 'S3MLS:%'
           OR m.body LIKE 'FILE:%')
), 0);

CREATE INDEX idx_conversation_members_read_cursor
    ON conversation_members (conversation_id, user_id, last_read_message_id);
