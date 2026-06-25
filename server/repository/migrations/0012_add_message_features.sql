-- 0012_add_message_features.sql
-- Extended messaging features.
--
-- 1. reply_to_message_id — foreign reference to the quoted/replied message
-- 2. message_reactions   — per-(message, user, emoji) reaction storage
--
-- NOTE: last_read_at is already present in conversation_members since
-- 0001_initial_schema.sql — no change needed here.

-- Reply / quote support: NULL means no reply, >0 means the replied-to message id.
ALTER TABLE messages
    ADD COLUMN reply_to_message_id BIGINT DEFAULT NULL;

-- Emoji reactions table.
-- UNIQUE on (message_id, user_id, emoji) prevents duplicate reactions.
CREATE TABLE IF NOT EXISTS message_reactions (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    message_id  BIGINT NOT NULL,
    user_id     INT    NOT NULL,
    emoji       VARCHAR(16) CHARACTER SET utf8mb4
                         COLLATE utf8mb4_unicode_ci NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_reaction (message_id, user_id, emoji),
    INDEX idx_message      (message_id),
    INDEX idx_user_reacts  (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
