-- 0001_initial_schema.sql
-- Complete initial schema for SecChat.
-- Incorporates all DDL that was previously inline in db.c (CREATE TABLE +
-- all ALTER TABLE additions).  Fresh installs get all columns from the start;
-- existing databases already have the tables so every CREATE TABLE IF NOT
-- EXISTS is a safe no-op.

-- ── users ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(64)  UNIQUE NOT NULL,
    email         VARCHAR(200) DEFAULT NULL,
    password_hash VARCHAR(200) NOT NULL,
    display_name  VARCHAR(100),
    bio           TEXT         DEFAULT NULL,
    avatar        MEDIUMBLOB   DEFAULT NULL,
    avatar_mime   VARCHAR(64)  DEFAULT NULL,
    status        ENUM('online','offline','away') DEFAULT 'offline',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen     DATETIME DEFAULT CURRENT_TIMESTAMP
                  ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email    (email),
    INDEX idx_status   (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── friendships ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS friendships (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id      INT NOT NULL,
    friend_id    INT NOT NULL,
    status       ENUM('pending','accepted','blocked') DEFAULT 'pending',
    requester_id INT NOT NULL,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
                 ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_friendship (user_id, friend_id),
    INDEX idx_user_status   (user_id, status),
    INDEX idx_friend_status (friend_id, status),
    INDEX idx_requester     (requester_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── conversations ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS conversations (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    type            ENUM('direct','group') DEFAULT 'direct',
    name            VARCHAR(100),
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
    last_message_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    creator_id      INT DEFAULT NULL,
    is_disbanded    TINYINT(1) DEFAULT 0,
    disbanded_at    DATETIME DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── conversation_members ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS conversation_members (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    conversation_id BIGINT NOT NULL,
    user_id         INT NOT NULL,
    joined_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_read_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    hidden_at       DATETIME DEFAULT NULL,
    UNIQUE KEY unique_member          (conversation_id, user_id),
    INDEX idx_user_conversations      (user_id),
    INDEX idx_conversation_members    (conversation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── messages ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    conversation_id BIGINT NOT NULL,
    sender_id       INT NOT NULL,
    body            LONGTEXT NOT NULL,
    sent_at         DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    edited_at       DATETIME(3) DEFAULT NULL,
    deleted_at      DATETIME(3) DEFAULT NULL,
    INDEX idx_conversation_time (conversation_id, sent_at DESC),
    INDEX idx_sender            (sender_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── user_keys ──────────────────────────────────────────────────────────────
-- Ed25519 identity record. Secret material is encrypted client-side before
-- being stored here.
CREATE TABLE IF NOT EXISTS user_keys (
    user_id              INT PRIMARY KEY,
    identity_pk          TEXT DEFAULT NULL,
    identity_sig         TEXT DEFAULT NULL,
    identity_sk_enc      TEXT DEFAULT NULL,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
