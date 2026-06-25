-- Disappearing messages must not erase history that existed before the timer
-- was enabled.  This timestamp marks the start of the active timer window.
ALTER TABLE conversations
    ADD COLUMN disappear_enabled_at DATETIME NULL AFTER disappear_after_secs;

