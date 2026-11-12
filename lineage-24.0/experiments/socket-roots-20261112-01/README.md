# Held-gate private-root bootstrap and activation

SocketRoots uses the real lease and explicitly selected g24sock CheckedUidChains.
It first requires the registered dual-stack snapshot-safe primitive (bit256),
then requires the shared gate to be held. Missing capability/protocol/I/O failure
closes the lease and leaves networking held. It never releases the gate or
publishes a backend-ready result. The enclosing sole backend must hold its full
transaction mutex across these operations, rule changes and UID/LNA publication.

Preparation inventories both families before its first write. Missing chains
are created only in an inert DROP table with no root jumps or user rules. It
creates only the eleven fixed names, never flushes or replays foreign text, and
verifies retained root policies/jumps and all user programs after creation.
Complete existing programs are checked and preserved. Partial creation remains
held and can be resumed with an explicit new lease.

Activation requires the already-installed exact complete ordinary image in both
families, including the compiler's fixed dispatch. It adds the two owned root
jumps before setting INPUT/OUTPUT ACCEPT. Exact roots and user programs are read
back in both families. A valid partial activation can be completed under a new
held lease. Any uncertain result closes the lease; no rollback/release is hidden
inside this component. This does not bootstrap metered/filter attachments, supply
VPN/IIF/accounting, attach the evaluator to packet hooks, or implement a complete
multi-table owner transaction/startup/Binder provider.

socket-roots-host-20261112-02 passes180 assertions, including failures before and
after every successful I/O point, missing capability, interrupted capability read,
invalid/foreign/duplicate roots, both-family validation before writes, retained
program drift, malformed/oversized/NUL output, partial recovery and no writes
without a held gate. Actual lease/checked/ordinary C++ is compiled with fatal
UBSan; syscalls, tables and packet context remain models. The first host attempt
stopped on a malformed-NUL fixture whose length omitted the NUL; the corrected
fixture and all failure evidence are retained. UID90, private-chain59 and original
filter84 regressions pass too.

socket-roots-native-20261112-01 compiles all six actual sources with Android17's
real ARM64 netd LTO/CFI command and partially links/validates their ELF symbols.
All five copied UAPI headers match the actual built kernel. Complete1243/17 source
audits before/after pass; production objects remain unchanged. This is compile/
link evidence, not a complete netd link, kernel syscall execution or hardware test.
