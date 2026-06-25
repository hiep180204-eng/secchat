-- 0011_add_privacy_settings.sql
-- Privacy controls for presence visibility.
--
-- Adds three ENUM columns to users controlling who can see:
--   privacy_online       — whether the user appears online
--   privacy_last_seen    — whether last_seen timestamp is visible
--   privacy_read_receipt — whether read receipts are sent to peers
--
-- Valid values: 'everyone' | 'friends' | 'nobody'
-- Default: 'everyone' (backward compatible — existing users keep full visibility)
--
-- NOTE: No IF NOT EXISTS — MySQL 8.0 does not support that syntax for ALTER TABLE.
-- Idempotency is handled by the migration runner (schema_migrations tracking table).
-- errno 1060 (duplicate column) is also silently ignored by migrate.c as a safety net.

ALTER TABLE users
    ADD COLUMN privacy_online
        ENUM('everyone','friends','nobody') NOT NULL DEFAULT 'everyone';

ALTER TABLE users
    ADD COLUMN privacy_last_seen
        ENUM('everyone','friends','nobody') NOT NULL DEFAULT 'everyone';

ALTER TABLE users
    ADD COLUMN privacy_read_receipt
        ENUM('everyone','friends','nobody') NOT NULL DEFAULT 'everyone';
