---
section: Fixed
issues: [#4812]
---
- **A replication task that a peer refuses for release immutability no longer retries forever** (#4812). When a peer answers a replicated upload or delete with `409 IMMUTABLE_RELEASE`, retrying can never succeed, yet the task landed in `failed` and the peer-recovery reset re-queued it on every backoff. Such a task now ends in a new terminal `refused` state (migration 297) with the peer's reason recorded. It is never retried, and the peer's failure counters and backoff are left alone because the peer is healthy. Every other error, including other `409`s such as a quarantine hold, keeps the existing retry behaviour. The peer sync-task API reports the new status as `refused`.
