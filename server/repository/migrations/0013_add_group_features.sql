-- 0013_add_group_features.sql
-- Group roles, description, avatar for conversations.
--
-- migrate.c handles idempotency via schema_migrations tracking.
-- Error 1060 (duplicate column) is suppressed so re-runs are safe.

ALTER TABLE conversations ADD COLUMN description  TEXT          DEFAULT NULL;
ALTER TABLE conversations ADD COLUMN avatar       MEDIUMBLOB    DEFAULT NULL;
ALTER TABLE conversations ADD COLUMN avatar_mime  VARCHAR(64)   DEFAULT NULL;

-- Group roles: admin / member per conversation.
-- Creator of a group gets role='admin' when the group is created (in groups.c).
CREATE TABLE IF NOT EXISTS group_roles (
    conversation_id BIGINT NOT NULL,
    user_id         INT    NOT NULL,
    role            ENUM('admin','member') NOT NULL DEFAULT 'member',
    granted_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (conversation_id, user_id),
    INDEX idx_conv_role (conversation_id, role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
