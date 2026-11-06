# Isolated guarded both-family UID-chain transactions

This composes the exact checked-chain I/O and real kernel lease transport
proposals. It takes an initially held lease and verifies actual ordered `-S`
readbacks: an unconditional private guard/DROP must be the first rule in INPUT,
FORWARD and OUTPUT in both IPv4 and IPv6. Missing, reordered, conditional,
wrong-target, malformed or excessive output is rejected. No hooks are installed.

Updates hold/drain the real shared kernel barrier, recheck hooks, capture both
actual before-images, update existing owned chains and verify both final images
and all six hooks before opening the gate. Failure attempts restoration of both
actual before-images, with final readbacks. Only a previously completed update
may be reopened after verified rollback; before the first commit the gate stays
held. Failed/unverifiable recovery or release invalidates the session and closes
the owned lease, rearming the barrier. No cache, callback or readiness is exposed.

62 fatal-UBSan cases run the actual three C++ components with scripted ordered
tables/device/sysfs/ioctls. Every table I/O asserts that the shared fixture gate
is held. Tests include both-family failures before/after commit, failed recovery,
failed post-commit release, first-transaction errors, invalid input and strict
six-hook ordering. Actual packets and kernel FD/RCU behavior remain untested.
Native verification compiles all three sources with actual Android17 netd ARM64
CFI flags and the real IptablesRestoreInterface header, then links one native
relocatable object. Full 1,243-project/17-patch source audits pass before/after.

The complete backend must be the sole rule owner and hold its outer firewall
transaction lock through publication. Hook installation/startup and restart
ordering, full UID/core/metered packet semantics, interface/VPN/LNA/permissions,
quota/CLAT/Java/DNS/lifecycle and truthful loader integration remain required.
This component is not selected into TOP or Android images and is not a complete
netd daemon, networking-ready signal or flashable ROM.
