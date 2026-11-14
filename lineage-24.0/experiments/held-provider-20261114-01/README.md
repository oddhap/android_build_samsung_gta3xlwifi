# Real held mainline provider initialization

Adds one explicit private C entry point to libnetd_updatable, preserving all three
existing APIs. Version/size/function pointers are checked, callbacks are copied,
and initialization verifies the real held owner and socket-owned qtaguid session.
Callbacks become immutable only after successful initialization. Default BPF
initialization/dispatch remains its original path. A failed or incompatible
private initialization cannot report BPF success or publish a callback set.

The explicit private main path initializes Controllers, then the provider, before
Netlink and Binder listeners. The stock cgroupv2/BPF path remains unchanged. The
entire main/DNS/oneshot source outside this narrow initialization is identical.
The provider calls the sole owner for atomic permission/budget/tagging controls.
Before the complete framework frame, operations return EAGAIN and traffic remains
held. Its successful initialization is deliberately a held transport phase, not a
networking Ready signal or a claim that BPF programs were loaded.

Host evidence: 23,026 owner assertions including every33 verification fault point
on both sides; 2,339 real socket/FD transport assertions with mocked driver I/O;
29 library-registration cases plus6,400 concurrent callbacks;21 actual adapter/
main-fragment order and cleanup cases. Existing startup29/guard960/packet99/
runtime71 regressions pass. The first native attempt stopped on an overly narrow
compiler-flag assertion: main uses CFI plus memtag-heap. Attempt02 recognizes the
actual original list and preserves every flag.

The actual18 server CFI sources, minSDK31 NetdUpdatable dispatch object and main
object compile. Both the complete provider DSO and complete netd link, with the
same dynamic dependencies and the old3/new4 exported C APIs checked. Actual
ARM32/64 checks bind callback size/offsets, qtag7151 and all nine kernel UAPIs.
Complete1,243-project/17-patch audits pass. Both unchanged strict policy binaries
pass22 permission queries, three genfs labels, enabled7151 contradiction and two
neighbor-denial compiler probes each. No policy grant/assertion was changed.

This is inactive source/build evidence. Soong source-list composition, actual
Java/Binder complete frames and delta ordering, statistics persistence/ACK,
UID/tag cleanup, CLAT's distinct privileged path and event delivery remain.
Boot init/NetBpfLoad admission still needs a real private-backend route: oneshot
is intentionally unchanged. Post-publication loopback smoke tests must be real;
held startup cannot exercise traffic. Final module, encryption, cgroup/zygote and
installer/packaging gates remain. No source/policy/prebuilt promotion, BPF object,
readiness property, tablet action or flash candidate is produced.
