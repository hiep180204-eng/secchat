-- SecChat: spec-aligned PQXDH bundle storage.
--
-- DM sessions fetch this PQXDH bundle before creating a Double Ratchet state.

CREATE TABLE IF NOT EXISTS pqxdh_bundles (
    user_id          INT PRIMARY KEY,
    identity_pk      TEXT NOT NULL,
    curve_spk_id     INT  NOT NULL,
    curve_spk        TEXT NOT NULL,
    curve_spk_sig    TEXT NOT NULL,
    pq_spk_id        INT  NOT NULL,
    pq_kem_alg       VARCHAR(32) NOT NULL,
    pq_spk           TEXT NOT NULL,
    pq_spk_sig       TEXT NOT NULL,
    version          INT NOT NULL DEFAULT 2,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
                     ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pqxdh_curve_one_time_prekeys (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT  NOT NULL,
    key_id      INT  NOT NULL,
    public_key  TEXT NOT NULL,
    signature   TEXT NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_curve_otk (user_id, key_id),
    INDEX idx_curve_otk_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS pqxdh_pq_one_time_prekeys (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT  NOT NULL,
    key_id      INT  NOT NULL,
    kem_alg     VARCHAR(32) NOT NULL,
    public_key  TEXT NOT NULL,
    signature   TEXT NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_pq_otk (user_id, key_id),
    INDEX idx_pq_otk_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
