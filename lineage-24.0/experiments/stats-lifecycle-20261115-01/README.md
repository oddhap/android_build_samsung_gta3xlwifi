# Durable consumer-state lifecycle without fake native acceptance

The inactive journal schema2 separates monotonic consumer-state revision from
real native bank/epoch acceptance. Metadata can be persisted before the first
poll with a genuinely absent receipt. Explicit compare-and-set amendments retain
an accepted receipt while updating complete consumer state, allowing UID cleanup/
network metadata to survive restore. Conflicting/stale updates and revision
exhaustion fail; uncertain writes require actual-file reload/reconciliation.
No fake epoch, automatic ACK/retry or baseline reset is introduced. Schema1 was
never selected or deployed; it is not silently reinterpreted as schema2.

The poller understands metadata-only records, detects disappeared/regressed state
revisions, and preserves cleanup when restoring before a new real frozen-bank
acceptance. Factory serialization and actual UID/kernel cleanup routing are still
required; test consumers are declared fixtures.

All four actual Java sources compile against original Connectivity SDK classes,
bind unchanged native prerequisites to the name-reader CFI/ARM32/64 proof and pass
1243/17 audits. Journal host tests pass312 checks (all previous corruption/file/
boot/epoch/durability cases plus metadata-only/CAS/cleanup/uncertainty/overflow).
Poll fixtures replay1467 client checks and pass61 flow cases, including metadata
before acceptance, genuine early HOLD, cleanup through restore, uncertain metadata
amendment and revision rollback. Android Os/AtomicFile/Binder/kernel/consumers are
explicit fixtures; no Android IPC, device power-loss or hardware proof is claimed.

Prerequisite: iface-names-20261115-01. Selected source, kernel/vendor/DTBO and policy
inputs remain unchanged. Actual NetworkStatsFactory/Service/TrafficStats consumers,
serializer, events/CLAT, source composition, full ROM and installation checks
remain. No flash candidate or networking Ready exists.
