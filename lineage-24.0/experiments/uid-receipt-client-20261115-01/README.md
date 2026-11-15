# Real kernel receipt transport and nonce-aware UID removal

Inactive uid-receipt-client24-20261115-01 over uid-cleanup-20261115-01 and the fully
built kernel-uid-receipt-20261115-01. No selected source/prebuilt/policy changes.

AIDL appends removeUidAccountingOnce as ordinal12 (thirteen methods total),
retaining all twelve prior signatures/ordinals. It requires fullUID1000, current
session and an explicit nonzero durable caller nonce. Kind5 reads actual cleanup
receipt metadata while verified held accounting is started, without claiming
packet statistics or networking readiness. The old non-receipted primitive is
retained for compatibility and must not be used for automatic crash recovery.

The actual lease verifies bit17 and exact64-byte wire/schema/identity/reserved
fields. Only READ retries EINTR. BEGIN and COMMIT are never blindly retried after
uncertain I/O. The owner checks a matching COMPLETE receipt before today's
publication generation fence: a previously completed request can be confirmed
after publication withdrawal without deleting newly created data for that UID.
New transactions validate generation/epoch and absence of pending banks, BEGIN,
perform real provider socket-tag deletion, then atomically COMMIT packet cleanup
and its receipt. PREPARED/uncertain state quarantines without replaying deletion.
Provider identity and real transport are unchanged; no new class data layout.

Validation:
- uid-receipt-owner-host02 passes26494 checks,92 new, replaying prior owner/service
  cases. Tests include cached completion after publication withdrawal/UID reuse,
  proper metadata before first policy, authorization/session fences, unsupported
  capability, malformed receipt, interrupted mutations and prepared-state refusal.
  Kernel receipt/packet/socket boundaries are explicit fixtures. This is not an
  Android restart or hardware test; real kernel receipt and qtaguid routines are
  independently covered by the preceding kernel/transport test packages.
- uid-receipt-client-native01 passes actual full CFI provider/transport/Controllers/
  owner/lease/service/netd/OEM,13-method AIDL compatibility, all12 actual Java
  sources, ARM32/64 receipt/name UAPI, exact fully built kernel header/Image
  binding and1243-project/17-patch before/after audits.
- uid-receipt-java-host01 replays1467 client,61 poll,326 consumer,12 factory,26
  TrafficStats and7 cleanup checks, then29 new metadata/nonce/uncertainty checks.
  Unsigned nonce/epoch bits survive transport; malformed data never becomes an
  empty receipt and uncertain mutations are not automatically retried.

Remaining: durable Factory UID-removal intent/nonce and startup admission,
explicit current/vendor strict ioctl6763 policy, complete NSS lifecycle/map/
listener/dump routing, terminal Java/session recovery, loopback, CLAT and final
source/Soong/APEX/full-ROM/installation checks. No flash-ready artifact exists.
