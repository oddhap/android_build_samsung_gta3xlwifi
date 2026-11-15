# Exact current-client terminal abort

Inactive terminal-abort24-20261115-01 over uid-receipt-client-20261115-01.
AIDL appends abortSession(session,token), ordinal13/fourteen methods total.
FullUID1000, exact current session and exact token precede native quarantine.
The production handler closes real HOLD/lease before existing netd exit/init
recovery. Old session IDs cannot abort even a reused token's newer published
session. Normal close, suspend and stop remain nonfatal. No daemon/device was
restarted by this work; production termination is tested through host boundaries.

StatsAccess, policy client and backend now request terminal abort for uncertain
transport/protocol failures. An explicit stale-session abort rejection does not
fall through to token-only close, preserving a newer reused-token owner. Retired
stats handles cannot issue more reads/mutations. UID cleanup ESTALE/EBUSY receives
a typed non-mutation rejection only after a genuine readGeneration confirms the
session remains live. No mutation is automatically retried.

Validation: terminal-abort-owner-host02 passes26528 assertions,33 new, including
an actually published replacement session before stale abort attempts. Actual
CFI netd/OEM/provider/Controllers/owner/lease/service, fourteen AIDL ordinals/API
compatibility,12 real Java sources, ARM32/64 UAPI, exact kernel binding and1243/17
audits pass in terminal-abort-native01. terminal-abort-java-host01 replays1467
client/61poll/326consumer/12factory/26traffic/7cleanup/29receipt checks and passes
15 new abort/retirement/rejection cases with explicit Binder/platform fixtures.

The native fatal callback is captured in owner tests; Android init/zygote restart
and hardware recovery remain untested. Durable factory UID intent/admission,
complete NSS lifecycle/maps/dumps, loopback/CLAT, final source/Soong/APEX, full ROM
and installation/encryption checks remain. No flash-ready artifact exists.
