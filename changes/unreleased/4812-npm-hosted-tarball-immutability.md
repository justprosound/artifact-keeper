---
section: Fixed
issues: [#4812]
---
- **A deleted npm release can no longer be republished with different bytes** (#4812). Hosted npm publishes store each tarball at `{package}/{version}/{name}-{version}.tgz`, but the release classifier only recognised the registry's `{package}/-/{name}-{version}.tgz` layout. It treated every hosted tarball as packument metadata, so the release-immutability check after a delete never ran. Hosted tarballs, including scoped `@scope/name/{version}/name-{version}.tgz`, are now release coordinates: different bytes at a deleted version answer `409 IMMUTABLE_RELEASE`, and identical bytes still republish. The npm-family formats that share the classifier (Yarn, pnpm) are covered too.
