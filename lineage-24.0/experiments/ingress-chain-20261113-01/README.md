# Typed native ingress state, compiler and root verification

Adds canonical IIF-present/index/lockdown and destination/two-interface state.
An explicitly present IIF0 remains stored and suppresses lockdown; clearing IIF
retains lockdown and emits an allowed-index0 DROP. Removal clears both. Selected
A17 capacities are20000 owner records and100 discard keys; the eventual complete
owner must enforce the SHARED owner-record union limit across other components.

Compilation requires the original ordered eleven-chain ordinary image. It keeps
the exact system/owner-skip/nine-UID prefix, inserts discard then per-UID IIF DROP
records in owner_in, and retains the final RETURN. owner_out is unchanged.
Adjacent identical IIF predicates merge into UID ranges. Typed encoder/readback
recognize only the two exact twelve-token numeric/hex forms; bad targets, indices,
addresses, combined predicates or placement fail validation. Filter-table use is
rejected. Existing1MiB/65536-rule checked-image limits remain: fragmented large
states may return E2BIG rather than silently omit enforcement. Capacity/scale
behavior needs review before a complete production backend is selected.

SocketRoots deliberately extends its exact prefix validator to accept only these
DROP tails in the correct order. Activation/verification with any ingress tail
requires real feature bits256 AND512 before any table I/O. It never releases the
gate or advertises backend readiness. A future COMPLETE backend startup must
require the v2 primitive even when its initial ingress state is empty; conditional
root checks alone are not a whole-backend version/attachment handshake.

Host02 passes72 control/parser/root assertions and1800 comparisons with separately
compiled, hash-bound actual A17 owner/discard C. Includes explicit wildcard/
lockdown transitions, UID removal,100/20000 state bounds and range merging,
both-family typed writes/readback, exact root activation, wrong-table rejection,
unsupported real capability quarantine before writes, invalid predicate/prefix/
tail ordering, and unchanged output root. Inherited180 root,90 lease,59 private
I/O and84 filter parser/rollback regressions pass. Syscalls/tables are fixtures;
the new rule evaluator covers ingress predicates, not a complete packet backend.
Host01 stopped on a test-macro initializer-comma issue; its evidence is retained.

Native01 exit0 at03:53:41UTC November13 compiles all seven sources with actual
Android17 ARM64 netd LTO/CFI flags and partially links/validates their ELF symbols.
All six copied UAPI headers match the actual built kernel.1243 projects/17 exact
patches before/after audits pass; production inputs/objects remain unchanged.
This is not a complete netd link, actual rule execution, publication/startup,
Binder integration or a flash-ready networking backend.
