-- 0014_add_identity_versioning.sql
-- Identity versioning for key rotation and safety number tracking.
--
-- identity_version is incremented atomically each time a user rotates their
-- identity key bundle (rotate_identity handler in services/keys.c).
-- All DM partners receive a safety_number_changed notification carrying the
-- new version so they know to re-verify the safety number.

ALTER TABLE user_keys ADD COLUMN identity_version INT NOT NULL DEFAULT 0;
