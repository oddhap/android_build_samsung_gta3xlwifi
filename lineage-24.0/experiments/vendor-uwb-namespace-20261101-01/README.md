# Samsung private UWB namespace — Android 17 recheck

**Isolated metadata experiment, not an image or installation candidate.**
The checksum-bound staging tool was rerun against the selected MTP vendor's
unchanged policy (`8df663eb65a807e6ee99f8b2384cb52d34c994a25087410486b1f88e278e2e53`).
It alpha-renames only the two vendor-private UWB types and the existing endpoint's
SELinux context. Original vendor, public versioned policy, endpoint name and
allow/neverallow rule counts are preserved. Inverse token replacement is exact.
No compiled policy, signing material, binaries or complete vendor tree is copied.

The same staging-tool source passes 18 fixture safety tests on Mac and Linux.
Actual Android 17 userdebug strict compilation still fails: 405 diagnostic blocks
versus the original 407. Exactly two diagnostic identities disappear, with no
new identities. The compiler hash and all other ordered policy input hashes are
identical; see `diagnostic-comparison.json` and the original/candidate reports.
No assertion-disabling compilation was performed for this Android 17 check.

This addresses the two named legacy/modern type collisions in the isolated
candidate. It does not resolve the remaining policy violations, prove Android 17
effective permission parity or validate callers/HAL behavior. The prior Android
16 TE-inspector results are historical evidence, not Android 17 validation.
The separated vendor types can lose permissions inherited accidentally from the
merged modern framework types. Review actual clients and image labeling/cache
invalidation before any image integration. No active source/prebuilt is changed.

`metadata.patch` is relative to extracted `etc/selinux`, not a Git project or
apply-port snapshot. Reproduce only through the checksum-bound tool into a fresh
outside-TOP metadata directory. Never replay it against a binary vendor image.
