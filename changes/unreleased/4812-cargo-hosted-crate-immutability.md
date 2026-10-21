---
section: Fixed
issues: [#4812]
---
- **A deleted crate version in a hosted Cargo registry can no longer be republished with different bytes** (#4812). Hosted crates are stored at `<name>/<version>/<name>-<version>.crate`, a layout the release classifier did not recognise, so it treated every hosted crate as a mutable index file and skipped the checksum comparison: yank, delete, then `cargo publish` of different bytes at the same version was accepted. That layout is now a release coordinate, so the republish answers `409` with `IMMUTABLE_RELEASE` in cargo's `errors` envelope, and the identical bytes still republish. The check also moved ahead of the storage write, so a refused publish no longer overwrites the stored crate. The sparse index and `config.json` stay mutable. Debian (`pool/`) and RPM (`.rpm`) hosted paths were audited and were already classified as releases.
