-- Migration 293: remember a released coordinate after storage GC reclaims its
-- tombstone (#4812).
--
-- Deleting a released artifact leaves a soft-deleted row, and the
-- release-immutability backstop compares every re-upload at that path
-- against it. Storage GC hard-deletes those rows once the trash retention has
-- passed -- on the next pass at the default GC_TRASH_RETENTION_DAYS=0 -- after
-- which the backstop had nothing to compare and accepted different bytes at
-- the released coordinate. GC now copies each reclaimed row's coordinate and
-- digest here, in the same transaction as the hard-delete, and the backstop
-- falls back to this table when no row is left at the path.
--
-- No bytes are kept: one small row per reclaimed artifact, retained
-- indefinitely. The first reclaimed digest wins (ON CONFLICT DO NOTHING), so
-- the record can only ever describe the bytes that were released.
--
-- An administrator's explicit permanent delete from the trash (#4700) stays
-- the deliberate way to reopen a coordinate; it removes the record too.

CREATE TABLE IF NOT EXISTS released_coordinates (
    repository_id   UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path            TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    version         TEXT,
    reclaimed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, path)
);
