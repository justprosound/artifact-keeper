-- Migration 292: per-repository release immutability policy (#4812).
--
--   repositories.release_immutability     -- 'off' (the default) keeps only
--       the always-on release rules; 'on' makes every non-exempt file path
--       immutable once stored, live or soft-deleted.
--   repositories.immutability_exclusions  -- '*' glob patterns, each matched
--       against every '/'-separated path segment; a matching path is exempt.
--
-- A text column with a CHECK rather than a Postgres enum, so a later mode can
-- be added by widening the constraint. Both defaults are constants, so the
-- ALTERs are catalog-only on PostgreSQL 11+ and every existing repository,
-- and every INSERT that names neither column, reads as 'off' with no
-- exclusions: no behaviour change.

ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS release_immutability TEXT NOT NULL DEFAULT 'off'
        CONSTRAINT repositories_release_immutability_check
        CHECK (release_immutability IN ('off', 'on')),
    ADD COLUMN IF NOT EXISTS immutability_exclusions TEXT[] NOT NULL DEFAULT '{}';
