# Ordinary UID policy to typed kernel-chain programs

This compiles the nine ordinary enabled/membership chain states into existing
owned g24_uid_1..9 typed chains. Disabled chains return. Enabled allowlists return
for members then drop; denylists drop members then return. Membership snapshots
are read-only, sorted and preserve output on errors. Only consecutive matching
UIDs are merged into inclusive ranges, without bridging gaps or overflowing
INT_MAX. The actual checked-chain encoder validates the complete image and byte/
rule limits before caller output is replaced. It performs no kernel I/O.

35 structural/input/overflow/output-preservation cases and1,048,576 comparisons
pass with fatal UBSan. The independent rule interpreter compares all512 enabled
and512 membership combinations for four app UIDs against the extracted ACTUAL
Android17 BPF isBlockedByUidRules expression and enums. This tests the ordinary
UID decision expression, not the whole BPF packet program or actual packet paths.
The three actual C++ sources compile with Android17 netd ARM64 CFI flags and link
as one real relocatable object; the actual IptablesRestoreInterface header and
complete before/after1,243-project/17-patch source audits are used.

Required dispatcher behavior remains outside this component: real core appId
exemption, ESP/TCP/direction/loopback behavior, verified attachments, metered
allow/deny/Data Saver, interface/VPN/LNA/permissions, quota/CLAT/lifecycle and
real Java/DNS/startup ownership. Metered configuration/membership does not alter
these nine images. No callback, readiness API, rule execution, complete netd
module or Android image selection is supplied. The earlier policy value's stale
A16 comments are corrected; current enum/expression comparisons use pinned A17.
