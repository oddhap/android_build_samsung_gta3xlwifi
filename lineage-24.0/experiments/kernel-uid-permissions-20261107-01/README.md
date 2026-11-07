# Isolated dynamic UID permission image and inet creation checks

Prerequisite: kernel-socket-peer-20261106-01. No Android prebuilt input changed.
Full kernel build kernel-uid-permissions-build-20261107-01 completed exit0 on
November7 14:54:46 UTC. Image SHA256:
660234ef810be218209ffd49bec80076a9734a29bda932468ded13a8cca5559c.
Configuration remains fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea.
All60343 candidate and60331 protected tracked sources, plus1243 Android project
revisions/17 patches, passed before/after audits. Gator118/KUTF43 imports match.

A new sparse RCU image stores the actual seven-bit A17 UidPermissionChunk
values. Absent UID returns0; NoInternet is the negative bit2, not an INTERNET
positive bit. Full replacement is sorted/unique, nonzero masks only, at most
65536 entries and signed-framework UID range. Input and allocation errors leave
the old image intact. Revision advances by1; an identical current revision is
idempotent. Publication precedes an RCU grace period before freeing old storage.
GET offers metadata then an exact-revision bounded data read. Revision0 means
uninitialized. Native/compat transfer layout is24 bytes; entries are8 bytes.

The old exclusive root/initial-CAP_NET_ADMIN/file/TGID lease is preserved. Exact
new operations are FEATURES0x6754, SET_IMAGE nr0x55 and GET_IMAGE nr0x56 (the last
two include direction/size bits). SET requires the actual shared gate held;
new dispatch never falls into the old RELEASE branch. Features describe only
real image and IPv4/IPv6 creation primitives, not complete networking readiness.
All prior device ownership, close/grace behavior and four-command ABI remain.

Both actual user inet creation paths check the current real UID in init_user_ns
after successful protocol initialization. NoInternet returns EPERM even for root
or control tasks. Kernel-created sockets retain the original path. During a
held transaction an otherwise permitted non-control app create returns EAGAIN;
trusted core appIds/initial-CAP_NET_ADMIN controls are exempt only from this
temporary hold. Failed protocol initialization and denied create each clean up
exactly once. Existing paranoid-network group checks remain unchanged.

Host81 cases and124608 comparisons passed with fatal UBSan, using actual image,
dispatch/create C bodies and the selected A17 migrated-create expression. Covers
input/copy/allocation faults, authentication, generation/idempotency/overflow,
sparse and maximum-sized images, exact readback, negative-bit semantics and both
inet tails. RCU/credentials/copies/socket effects are fixtures, not real kernel
runtime proof. Original44 lease/grace/mutex-contention regressions also pass.
Attempts01-05 failed only in harness extraction/setup/compilation or expectations:
MPTCP conditional signature, missing exported old header, missing concatenation
newline, assertion-count threshold, and NoInternet priority over temporary hold.
No production source changed to satisfy these failed fixture expectations.

Not implemented by this proposal: Java/native authoritative provider, combined
permission/rule transaction rollback, LNA, loopback permission packets/metrics,
VPN/IIF/DNS/CLAT or final attachments. Exact current-platform/vendor SELinux
ioctl grants are tested separately and are not selected automatically. The
kernel is not a standalone Lineage21-compatible replacement or a flash candidate.
