# Bounded complete-policy Binder transport

An append-only OEM getter exposes a private five-method interface without changing
frozen INetd18 or old OEM ordinals0/1. The getter and every RPC require the full
system UID1000. A real remote Binder token owns a monotonic process session and
is linked to death. Old sessions, other clients, duplicate starts and reordered
chunks are rejected. Neither a session nor successful handle lookup is Ready.

Ten explicitly counted sections carry users, known UIDs, raw permissions, every
chain's configuration/membership, IIF/lockdown, ingress discard, both LNA tables
and legacy blocked UIDs. Chunks contain at most4096 integers, with bounded complete
storage. A frame compiles through the existing permission/ordinary/ingress/LNA
validators before any owner/kernel operation. All twelve chain configurations,
current full-UID mode and runtime flags must be explicit. Observed INTERNET-only
canonical zero, missing-known NoInternet and actual core permission rows remain.

Commit uses the sole owner's generation CAS and returns that exact generation
under its transaction mutex. Attempted commits clear staging; no uncertain I/O
retry occurs. Client death clears staging and publication, verifies real HOLD,
and keeps the producer lease for explicit complete resnapshot. A failed HOLD
closes/quarantines it. Generation counters continue across clients. Stale queued
death callbacks cannot revoke a newer session.

Actual AIDL generates C++ and Java; real Java client stubs compile. Current AIDL
API checking accepts the append-only extension and old ordinals are checked.
Actual Android17 CFI owner/frame/service/getter compilation, complete OEM DSO and
complete netd linking pass with unchanged dynamic dependencies. Full1243-project/
17-patch before/after audits pass. Native01 missed the new interface in API dump
inputs; native02 fixes that tool input and passes with unchanged production source.

Host02 passes25,709 assertions, including2,682 new frame/service checks, the full
prior provider regression,65536-known-UID boundary,128 permission/chunk partitions,
all RPC identities,40 generation updates, malformed/partial/duplicate input,
client death/resnapshot/stale death and both sides of HOLD failures. The host
Binder/driver/table fixtures are explicit; actual IPC/packets are not executed.
Host01's capacity fixture omitted the two actual core rows; corrected fixture
includes them within the65536 limit. Both attempts are preserved.

The active checkout/prebuilts/policies remain unchanged. Java collection/routing,
reconnect/query lifecycle and Soong source-list composition are unfinished;
this is not a ROM or network readiness. Boot admission, CLAT/stats/event lifecycle
and the final installer/encryption/module/cgroup gates still need completion.
