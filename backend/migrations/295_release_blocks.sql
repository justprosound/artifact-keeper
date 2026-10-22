-- Migration 295: the release blocklist (upstream #4812, P2).
--
-- A block revokes a release without deleting or overwriting it. The bytes and
-- the artifact rows stay where they are, so the immutability backstops keep
-- comparing a re-publish against them, but no file of a blocked release can be
-- downloaded.
--
-- A block lives in its own table rather than as another `quarantine_status`
-- value. `quarantine_status` is per file and scan-driven: a re-scan, a
-- quarantine release or a trash restore all rewrite it. None of them touches
-- this table, so none of them can lift a block.
--
-- A coordinate is either a version, `(name, version)`, which blocks every
-- file of that version, or a single `path`, for formats whose files have no
-- version. Exactly one of the two shapes is set.
--
-- `mode` is `block` for now. The soft "yank" mode (#14) widens the named
-- CHECK constraint rather than adding a column.

CREATE TABLE IF NOT EXISTS release_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name VARCHAR(512),
    version VARCHAR(255),
    path VARCHAR(2048),
    mode VARCHAR(16) NOT NULL DEFAULT 'block',
    reason TEXT NOT NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_name VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT release_blocks_mode_check CHECK (mode IN ('block')),
    CONSTRAINT release_blocks_reason_check CHECK (length(btrim(reason)) > 0),
    CONSTRAINT release_blocks_coordinate_check CHECK (
        (name IS NOT NULL AND version IS NOT NULL AND path IS NULL)
        OR (name IS NULL AND version IS NULL AND path IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS release_blocks_version_key
    ON release_blocks (repository_id, name, version)
    WHERE path IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS release_blocks_path_key
    ON release_blocks (repository_id, path)
    WHERE path IS NOT NULL;
