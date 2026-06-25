-- MLS RFC 9420 runtime storage.
-- Server stores public/routing artifacts only. MLS secrets remain on clients.

CREATE TABLE IF NOT EXISTS mls_key_packages (
    id                         BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id                    INT NOT NULL,
    key_package_ref            VARCHAR(128) NOT NULL,
    ciphersuite                VARCHAR(128) NOT NULL,
    credential_identity_b64    TEXT DEFAULT NULL,
    key_package_b64            LONGTEXT NOT NULL,
    secchat_identity_version   INT NOT NULL DEFAULT 0,
    secchat_signature          TEXT DEFAULT NULL,
    claimed_at                 DATETIME(3) DEFAULT NULL,
    claimed_by                 INT DEFAULT NULL,
    created_at                 DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY unique_mls_key_package (user_id, key_package_ref),
    INDEX idx_mls_key_package_unclaimed (user_id, claimed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS mls_group_state (
    conversation_id       BIGINT PRIMARY KEY,
    group_id_b64          VARCHAR(256) NOT NULL,
    epoch                 BIGINT NOT NULL DEFAULT 0,
    last_commit_ref       VARCHAR(128) DEFAULT NULL,
    last_group_info_b64   LONGTEXT DEFAULT NULL,
    updated_at            DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3)
                          ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS mls_pending_group_ops (
    operation_id     VARCHAR(64) PRIMARY KEY,
    conversation_id  BIGINT NOT NULL,
    actor_id         INT NOT NULL,
    operation        VARCHAR(32) NOT NULL,
    target_user_id   INT DEFAULT NULL,
    role             VARCHAR(16) DEFAULT NULL,
    details_json     LONGTEXT DEFAULT NULL,
    status           ENUM('prepared','applied','rejected') NOT NULL DEFAULT 'prepared',
    created_at       DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    expires_at       DATETIME(3) NOT NULL,
    INDEX idx_mls_pending_conv (conversation_id, status),
    INDEX idx_mls_pending_actor (actor_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS mls_group_handshake (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    conversation_id  BIGINT NOT NULL,
    sender_id        INT NOT NULL,
    target_user_id   INT DEFAULT NULL,
    kind             ENUM('welcome','commit','group_info','control') NOT NULL,
    epoch            BIGINT NOT NULL DEFAULT 0,
    operation_id     VARCHAR(64) DEFAULT NULL,
    mls_message_b64  LONGTEXT NOT NULL,
    created_at       DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    INDEX idx_mls_handshake_conv (conversation_id, id),
    INDEX idx_mls_handshake_target (target_user_id, id),
    INDEX idx_mls_handshake_op (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
