-- Persist group membership/system events as timeline metadata.
-- Message bodies remain E2EE ciphertext in the messages table; these rows are
-- server-visible membership metadata used only to render stable group history.

CREATE TABLE IF NOT EXISTS group_system_events (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    conversation_id  BIGINT NOT NULL,
    event_type       VARCHAR(32) NOT NULL,
    actor_id         INT NOT NULL DEFAULT 0,
    target_user_id   INT NOT NULL DEFAULT 0,
    role             VARCHAR(16) NOT NULL DEFAULT '',
    operation_id     VARCHAR(64) NOT NULL,
    after_message_id BIGINT NOT NULL DEFAULT 0,
    members_json     LONGTEXT DEFAULT NULL,
    created_at       DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY unique_group_system_event
        (conversation_id, operation_id, event_type, target_user_id, role),
    INDEX idx_group_system_timeline (conversation_id, after_message_id, id),
    INDEX idx_group_system_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
