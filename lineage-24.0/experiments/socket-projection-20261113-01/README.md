# One-lease four-state socket policy projection

SocketPolicyProjection owns ONE genuine lease and mutex across ordinary/ingress
in private g24sock, metered rules in filter, the two LNA stores and seven-bit UID
permissions. It requires all ten real primitive bits at startup, including v2
metadata/ingress even when the initial state is empty. Startup stays held and
unpublished. It preserves the existing six-guard capture/install/check logic.

All four candidate values are validated/allocated first; shared owner admission
counts the actual union of all twelve UID chain memberships and IIF/lockdown
records, including disabled chains and explicit wildcard0. More than20000 distinct
owners returns E2BIG before HOLD/I/O and leaves the prior committed state intact.
Checked-image size limits still apply separately.

Under HOLD it verifies roots/parents, captures every private/filter before-image
and actual UID/LNA revision/value, rejects drift against the last commit, updates
both tables in both families, activates/verifies both parent graphs and rechecks
all six guards. All firewall work ends before LNA SET/readback, then UID SET/
readback LAST. RELEASE precedes one nonthrowing committed-pointer publication.
There is no post-SET firewall query/rollback and no release of mixed state. Any
uncertainty withdraws EVERY value and closes/holds the gate, including when a
component managed its own local rollback. An explicit new start/full replacement
is required after quarantine; it never repairs foreign policy automatically.

Generation-checked replacement rejects stale snapshots before I/O. Mutators copy
all four values, preserve unrelated components and share the complete transaction;
UID removal clears ordinary, ingress, permissions and UID-specific LNA entries.
Snapshot readers lock the same owner. Event consumption uses the same real lease/
mutex; failure withdraws values instead of faking an empty stream. No FD is exposed.
This is policy projection, NOT traffic accounting, event delivery/worker, complete
netd linking, Binder/Java/source startup integration or global network readiness.

Host02 passes990 assertions: faults before/after all28 startup and102 first-update
ioctl/firewall points, failure after a prior publication, real cutoff instrumentation
that asserts on ANY firewall operation after the first image SET, genuine-capability
absence (each bit), state generation/stale rejection, shared-union overflow,
concurrent unrelated mutators, four-component UID removal and consuming-event
failure. The root-NoInternet control corner remains honestly fail-closed: it is
not auto-cleared/bypassed to create raw control sockets. Syscalls/tables are modeled.
Host01 stopped on fixture indentation; source/audit/failure evidence retained.

Native01 exit0 at10:50:47UTC November13 compiles all twelve actual sources with
Android17 ARM64 netd LTO/CFI flags and partially links/validates their ELF symbols.
Six UAPI bindings and1243 projects/17 patches before/after audits pass. A separate
object-hash-bound namespace audit finds no unresolved private policy namespace
symbols; platform/library resolution and full netd integration remain required.
Production source/objects and selected kernel/vendor/DTBO remain unchanged.

Next: explicitly port BandwidthController initialization to prepare empty/known
parents without BPF rules and route its controls to this owner, then genuine
accounting and private Binder/Java/startup/metrics delivery. Frozen INetd18/OEM
ABI, strict SELinux/platform+vendor assertions, encryption/rollback/installer and
final OTA gates remain. No prebuilt selection, binary publication or flashing.
