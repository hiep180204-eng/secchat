-- User blocking and offline notification queue

CREATE TABLE IF NOT EXISTS user_blocks (
    blocker_id  INT NOT NULL,
    blocked_id  INT NOT NULL,
    blocked_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (blocker_id, blocked_id),
    INDEX idx_blocked_by (blocked_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS notification_queue (
    id         BIGINT NOT NULL AUTO_INCREMENT,
    user_id    INT NOT NULL,
    type       VARCHAR(64)  NOT NULL,
    payload    TEXT         NOT NULL,
    is_sent    TINYINT NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_pending (user_id, is_sent)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
