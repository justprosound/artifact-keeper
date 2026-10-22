-- Migration 297: a terminal `refused` state for replication tasks (#4812).
--
-- A peer that refuses a replicated write or delete for a release-immutability
-- reason answers 409 with the stable code IMMUTABLE_RELEASE. Retrying can never
-- change that answer, yet the task used to land in `failed` and the peer
-- recovery reset re-queued it on every backoff, forever. `refused` is terminal:
-- the worker records the peer's reason and never retries it. The peer is not
-- penalised (it is healthy; it said no).
--
-- PostgreSQL 12+ accepts ADD VALUE inside a transaction (the new label just
-- cannot be used in the same transaction, and this migration does not).

ALTER TYPE sync_status ADD VALUE IF NOT EXISTS 'refused';
