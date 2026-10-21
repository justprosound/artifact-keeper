---
section: Fixed
issues: [#4812]
---
- **Storage GC no longer reopens a deleted release for different bytes** (#4812). Deleting a released artifact leaves a tombstone, and the release-immutability backstop refuses a re-upload of different bytes against it. Storage GC hard-deletes those tombstones once the trash retention has passed, which is the next GC pass at the default `GC_TRASH_RETENTION_DAYS=0`. After that the backstop had nothing to compare against, and anyone with delete and write permission could put different bytes behind a released version. GC now records each reclaimed coordinate and its digest in a new `released_coordinates` table (migration 293, one small row per reclaimed artifact, no bytes), and the backstop falls back to it. Re-uploading the identical bytes still succeeds. An administrator's permanent delete from the trash (#4700) remains the deliberate way to reopen a coordinate, and it removes the record as well.

  At the default `GC_TRASH_RETENTION_DAYS=0` the next hourly GC pass reclaims a deleted release, so an administrator who wants a coordinate back for *different* bytes has until then to permanently delete it from the trash. After that, only the original bytes can be republished there, until the audited override lands. Coordinates GC reclaimed before this release are not backfilled; the record only covers reclaims from now on.
