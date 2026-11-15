# Real TrafficStats reads and held counterset metadata

Inactive candidate traffic-stats24-20261115-01 over stats-factory-20261115-01.
No selected source/prebuilt/policy changes and no flash-ready package exist.

The actual NetworkStatsService UID/iface/total entry points now select a shared
StatsAccess consumer for this product, preserving their existing full-calling-UID
privacy check and provider adjustment paths. Reads use genuine nonconsuming app
and interface tables. Specific interface reads resolve retained kernel names;
total reads need no name lookup. Complete lossless table absence returns zero
with the same meaning as ENOENT in the pinned A17 bpfGetUidStatsInternal and
bpfGetIfaceStatsInternal. HOLD, loss, missing interface history, signed range
failure, malformed/uncertain IPC or overflow report unavailable, never zero.

Foreground/background countersets use the real private stats ioctl. The service
updates its cached set only after successful kernel mutation. The native owner
allows this metadata operation after verified accounting startup even while
HOLD remains active; it does not publish policy or release traffic. Reads,
SWAP/ACK and UID deletion retain their prior committed-policy requirements.
Before startup and after stop metadata is unavailable. Invalid input remains
rejected and uncertain I/O retains the fatal quarantine behavior.

Validation:
- counterset-held-host01 passes26339 assertions, replaying prior owner, service,
  DNS, stats, interface and fatal cases. Two old prepublication admission
  expectations are explicitly updated for the intended metadata behavior.
  New checks prove held traffic, generation0, read denial and input boundaries.
- traffic-stats-native01 passes actual CFI Controllers/owner/lease/service/netd,
  OEM DSO,11 unchanged AIDL ordinals/API compatibility, ARM32/64 UAPI, all12 real
  Java sources against current Connectivity+service-t classpaths, and1243/17
  before/after source audits. Its conservative whole-framework-readiness field
  remains false: whole product integration has not been performed.
- traffic-stats-host01 replays1467 client cases,61 poll flows,326 consumer and
  12 actual factory assertions, then passes26 TrafficStats/privacy/counterset
  checks. Actual service UID-entry/helper/foreground/setter method bodies are
  extracted verbatim and compiled with explicit Binder identity, permission,
  BPF-map, logging and platform API fixtures. These are host boundary fixtures,
  not Android permission/hardware validation. Full service SDK compilation is
  separate. UID0 and user-offset UID101000 do not gain systemUID1000 access.

Remaining service work includes actual BPF-map/SkDestroyListener initialization
selection, complete UID/socket cleanup, and private diagnostic dumps. Existing
kernel socket tags are genuinely socket-owned; no fake cookie map/listener will
replace them. Remaining port gates also include loopback event delivery, CLAT
raw-socket lifecycle, source/Soong/APEX composition, strict selected policy,
full build and installation/encryption/partition checks.
