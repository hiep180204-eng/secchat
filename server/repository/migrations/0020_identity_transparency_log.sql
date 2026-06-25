-- Identity transparency log for SecChat key history.
--
-- The chat server writes one append-only row for the initial identity key and
-- one row for every explicit rotate_identity call.  The auditor service reads
-- this table, builds a Merkle tree, signs checkpoints, and serves proofs to
-- clients.

CREATE TABLE IF NOT EXISTS identity_key_log (
    log_index        BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id          INT NOT NULL,
    identity_version INT NOT NULL,
    identity_pk      TEXT NOT NULL,
    device_id_hash   VARCHAR(64) NOT NULL DEFAULT '',
    device_label     VARCHAR(128) NOT NULL DEFAULT 'primary device',
    event_type       ENUM('initial','rotation') NOT NULL,
    created_at       VARCHAR(32) NOT NULL,
    leaf_hash        CHAR(64) NOT NULL,
    UNIQUE KEY unique_identity_log_version (user_id, identity_version),
    INDEX idx_identity_log_user_version (user_id, identity_version),
    INDEX idx_identity_log_leaf (leaf_hash),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
