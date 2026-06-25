-- MLS PQ hybrid public validation state.
-- Existing group state is reset in deployments for this migration; new groups
-- must be X-Wing draft hybrid (ML-KEM-768 + X25519) with Ed25519 signatures.

ALTER TABLE mls_group_state
    ADD COLUMN ciphersuite VARCHAR(128) NOT NULL
        DEFAULT 'MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519',
    ADD COLUMN public_state_b64 LONGTEXT DEFAULT NULL,
    ADD COLUMN public_state_hash VARCHAR(128) DEFAULT NULL,
    ADD COLUMN validation_backend VARCHAR(64) DEFAULT NULL,
    ADD COLUMN validated_at DATETIME(3) DEFAULT NULL;
