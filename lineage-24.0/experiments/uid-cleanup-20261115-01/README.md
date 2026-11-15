# Fenced native UID/socket cleanup primitive

Inactive uid-cleanup24-20261115-01 over traffic-stats-20261115-01. No selected
source, prebuilt, policy or device changes. This is not complete NSS UID removal.

The actual provider dispatch validates its existing owner identity and passes
its existing QtaguidTransport to the owner via a native-only deletion function.
The private AIDL appends ordinal11 (twelve methods total); every call requires
fullUID1000 and the active session. The owner serializes exact policy generation
and active statistics epoch checks, rejects pending banks, then deletes actual
qtaguid socket tags before packet/app/counterset records. Held generation0 is
allowed only after real accounting startup and an actual held-state check.
Mismatch and busy rejection precede the socket mutation. Uncertain transport,
protocol or kernel failures quarantine the owner; no automatic mutation retry.
The Java API retains unsigned epoch bits and retires uncertain sessions.

Qtaguid d0UID is one complete bounded command, not a fictional socket FD. Normal
socket tag/untag validation is unchanged. Deletion errors/short writes close the
real transport. No class data members or transport vtable layout were added.

Validation:
- uid-tag-cleanup-host02:3006 actual transport assertions,667 new; real host
  IPv4/IPv6 TCP/UDP/dup/FD tests with explicit proc/sysfs/device boundaries.
- kernel-uid-tag-cleanup-host01:46488 checks,534 new, using actual unchanged
  ctrl_cmd_delete/tag-ref retirement with declared kernel primitive fixtures.
- uid-cleanup-owner-host03:26401 checks,61 new; actual owner/service and verbatim
  provider-identity dispatch, explicit packet-store/socket-delete boundaries.
- uid-cleanup-native01: actual provider/transport/Controllers/owner/lease/service
  CFI netd/OEM links, append-only12-method AIDL compatibility, ARM32/64 UAPI,
  all12 actual Java sources and1243/17 before/after audits pass.
- uid-cleanup-java-host01:1467 client,61 poll,326 consumer,12 factory,26 traffic,
  and7 new cleanup checks pass. Uncertain cleanup is never retried by the API.

Earlier transport01 used obsolete pre-quarantine fixture expectations. Owner01
had an invalid pending-bank epoch; owner02 included startup reads in a later
no-I/O assertion. These fixture failures and their logs remain on the server.
The production candidate did not change to satisfy those fixture corrections.

Remaining: durable NSS/factory intent, completed-operation deduplication and
startup admission. Ingress counters explicitly continue counting dropped ingress
while HOLD is active in the actual kernel: HOLD must never be treated as proof
that all counters are unchanged. Blind UID deletion replay after a restart can
lose a new app's counters/tags if the UID was reused. The API is therefore not
wired into NSS lifecycle yet. Final map/listener selection, loopback, CLAT,
source/Soong/APEX integration, full ROM and installation checks remain pending.
