# Isolated implemented policy-capability profile

This candidate accepts only bits 0,1,2,3,5,9,12, backed by the actual implemented
network/open/extended-socket/NNP/netlink/FunctionFS paths. It replaces the earlier
blanket netlink rejection after real-policy netlink/AVC comparisons. It rejects
every other active bit instead of silently ignoring unsupported capabilities.
All original fail-closed panic handling remains. The enum comment changes without
an enum/value/layout change. No neverallow or runtime enforcement flag changes.

Development comparisons used the one-bit-off parser control and an explicit
active-mode fixture. The definitive post-build test instead uses the unmodified
diagnostic binary and actual capability decoding. No capability bit is forced,
no guard skipped and no modified control binary used in this definitive test.
Strict vendor policy remains failed; its init-style diagnostic binary is never
an installation policy. Complete standalone compilation and definitive post-build checks finish exit 0.
The unchanged 1,485,206-byte diagnostic input now parses and uses the actual
security_load_policycaps body. All 16,384 capability combinations and four sparse
unknown-bit controls behave as specified: 128 subsets accepted, 16,256 rejected.

For 8,192 real-policy queries across eight domains, four netlink classes, four MLS
pairings, both namespaces and four driver bytes, there are zero differences from
Android17 libsepol. Actual SID, mapping, constraint/MLS/bounds, service, AVC and
skb bodies execute. Checks cover 6,291,456 AVC commands, 3,145,728 single packets,
73,728 compound packets, 61,440 malformed/short packets, 12,288 absent-security
cases and 60 simulated generation changes. Both grants (52,524) and denials
(6,238,932) occur in the AVC corpus. Cache modes include cold, base-only and
extended decisions with a real-policy opposite-namespace decoy. The oracle uses
independent libsepol parsing/base decisions and attribute/AVTAB traversal; its
permission-name projection uses the actual kernel vocabulary, not kernel results.

Full 60,331-file candidate/protected before/after audits pass, and host-after
sources match too. Config/firmware stay exact. All 8,408 export CRCs and complete
Module.symvers bytes match the firmware parent; its 1,104 differences from the
original kernel remain. Image SHA256:
`5d3b21c1a9abb1e7c5175670606f9486c8a5da8f8ad536c132c5bd9c6c350fb2`.

Fixture preparation first failed on header search order, metadata initializers
and linkage declarations. An extra host sidtab_init caused a leak because the
real policydb_load_isids initializes it itself; only the duplicate fixture call
was removed. Compiler/sanitizer checks stayed enabled. Initial runner generation
also failed before producing source/jobs due to a heredoc delimiter collision;
its failed launch log is retained, and the corrected launcher uses a separate
log. No kernel failed result was reclassified as a pass.

Memory/cache/RCU/lock, task/socket/skb metadata and audit backends are sequential
host fixtures. No kernel boot, concurrent reload, native cache, full ABI or
hardware proof. Networking/BPF, strict vendor policy and FBE/installer remain
gates. No Image promotion or physical changes.
