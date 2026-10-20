---
section: Fixed
issues: [#4812]
---
- **A deleted sbt release's Ivy descriptor can no longer be replaced with different content** (#4812). `ivy.xml` and `ivy-<rev>.xml` (and their checksum and signature files) were classified as mutable index files, so after deleting a release version a different descriptor could be uploaded at the same revision, changing the dependencies and configurations that clients resolve for a version they already pinned. A descriptor under a concrete revision is now treated as part of the release: re-uploading different bytes after a delete answers `409 IMMUTABLE_RELEASE`, the identical bytes are still accepted, and a remote sbt repository caches it like the release's jars. Descriptors under `-SNAPSHOT`, `latest.*` and dynamic revisions stay re-uploadable.
