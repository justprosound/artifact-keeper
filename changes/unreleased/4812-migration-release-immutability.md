---
section: Fixed
issues: [#4812]
---
- **A migration no longer replaces the bytes of a released artifact** (#4812). The migration write upserts on `(repository, path)`, and `Overwrite`/`Rename` re-process every item while `Skip` re-processes any item whose declared checksum differs, so a run could rewrite a released version in place or resurrect a deleted release with different bytes. The write now applies the same release-immutability backstop as uploads: such an item is skipped and its reason names the immutability conflict, the job does not fail, and the release keeps its bytes. Re-migrating identical bytes, and replacing an unversioned path, behave as before.
