# Policy 30.0 mapping investigation for Android 17

**Isolated candidate only. No mappings, policy or vendor images are installed.**

The first Android 17 native/policy build passed, including both-ABI Audio HIDL4,
Bionic and VNDK30. That built platform policy but did not link the actual Samsung
Android 11 vendor policy. The real MTP vendor image still declares policy 30.0.
Android 17's source/build outputs start at 31.0: private compatibility 30.0 and
its installed mapping are absent. The ordinary checker correctly stops there.

The reference files come verbatim from the prior revision-locked LineageOS 23.2
system/sepolicy commit `885cc500f6078a766d1f6def5ce4c06c55841773`. The source lock
records their original paths and SHA-256 digests. The Android 17-built official
`combine_maps` tool composes the current installed 31.0 map with that exact
30.0 input, entirely outside Android TOP. The companion 30.0 compatibility
fragment is used unchanged. All tools and policy inputs are hash-bound before
and after the probe. The actual MTP vendor image was independently checked as
sparse SHA `a847a527...` and raw SHA `cb142676...` before read-only debugfs extraction.

The source/runtime genfs default is 202404; no fragment exists for that default,
matching the current init behavior. No empty APEX inventory or kernel/BPF support
is invented. Full system_ext/product 30.0 mapping installation remains unfinished.

The reproducible `tools/probe-policy30.py` experiment retains **strict neverallow
checking**. Actual result: **exit 255, 407 neverallow diagnostics**, no unresolved
symbols reported. This is not a security pass, production-ready compatibility
layer, kernel policy-loader test or runtime approval. It is a concrete starting
point for restoring the old metadata contract and reviewing real cross-version
conflicts. The log includes vendor application ptrace conflicts, modern service
access constraints and historical private-type collisions; do not remove
neverallows or grant broad exceptions to make it pass.

The next source change needs reviewed 30.0 build-module/API compatibility support,
source-bound compatibility tests and precise conflict analysis. Continue outside
TOP while another build runs; publish a new snapshot only after review and audit.
