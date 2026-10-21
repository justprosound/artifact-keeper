---
section: Fixed
issues: [#4812]
---
- **Promotion and approval can no longer swap the bytes behind a released, deleted version in the target repository** (#4812). Deleting a released artifact leaves a tombstone so the same version cannot be re-uploaded with different content, but promote, bulk promote and approve-and-execute purged that tombstone unchecked and copied the source's bytes over it. They now refuse with 409 before any byte is copied or the approval is spent: the tombstone and its stored bytes stay intact, an approval stays `pending`, a bulk item fails with an "immutable" message while the rest of the batch continues, and each refusal is audited as `PROMOTION_REFUSED`. Promoting the identical bytes onto the tombstone still succeeds.
