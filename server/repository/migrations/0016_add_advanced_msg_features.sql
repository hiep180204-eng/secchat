-- Pin messages, forward, disappearing messages, conversation preferences, mark unread

CREATE TABLE IF NOT EXISTS pinned_messages (
    conversation_id BIGINT NOT NULL,
    message_id      BIGINT NOT NULL,
    pinned_by       INT    NOT NULL,
    pinned_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (conversation_id, message_id),
    INDEX idx_pm_conv (conversation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE messages ADD COLUMN forwarded_from_id BIGINT DEFAULT NULL;

ALTER TABLE conversations ADD COLUMN disappear_after_secs INT DEFAULT NULL;

ALTER TABLE conversation_members ADD COLUMN muted_until    DATETIME DEFAULT NULL;
ALTER TABLE conversation_members ADD COLUMN archived_at    DATETIME DEFAULT NULL;
ALTER TABLE conversation_members ADD COLUMN conv_pinned_at DATETIME DEFAULT NULL;
ALTER TABLE conversation_members ADD COLUMN force_unread   TINYINT  NOT NULL DEFAULT 0;
