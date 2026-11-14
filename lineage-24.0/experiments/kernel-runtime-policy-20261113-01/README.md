# Explicit Android 17 runtime network policy image

Real independent loopback checks/metrics and migrated-versus-legacy local-network
selection. Legacy true blocked UIDs are a sorted immutable bounded image; false
and absent entries are equivalent in the actual A17 decision. Updates require
the existing root/init-capability, owner file/TGID and held lease. No automatic
feature disabling, BPF objects or networking Ready is introduced.

The real 32-byte versioned GET/SET protocol exposes flags, revision, canonical
UIDs and confirmation for this lease. Opening/revoking a lease invalidates its
confirmation, while retaining image metadata for explicit recovery. RELEASE
rejects an unconfirmed runtime configuration. SET uses next revision or exact
idempotent receipt and has no fallible copy after publication. GET is
non-consuming. Unknown flags/UIDs, duplicates, stale revisions and overflow fail.

Four loopback combinations and both LNA modes run against actual pinned A17
predicate bodies. Unrelated legacy fixtures explicitly select their original
enabled/migrated mode; they do not stand in for runtime validation. Complete
source identity outside the intended predicate and dispatch changes is retained.
The native runtime transport/five-state owner and exact strict policy grants now
pass isolated validation; see the November 14 checkpoint in the main README.
Actual service integration remains required before production activation.
No tablet access, selected source/prebuilt change or flash candidate.
