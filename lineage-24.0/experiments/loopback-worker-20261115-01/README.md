# Android handler delivery of genuine loopback events

Inactive Java-only delta over loopback-rpc-20261115-01. All native/AIDL/kernel
prerequisites remain exact, including validated append-only RPC15. The real
BpfNetMaps singleton starts one process-wide consumer using its existing native
session. Actual ConnectivityService.systemReady selects it only for the private
backend and preserves the original BpfEventPoller initialization elsewhere.

The actual handler worker consumes one bounded batch every100ms, validates through
StatsAccess, and reports the existing A17 LOOPBACK_USAGE_REPORTED atom1216.
Sender and receiver fields carry IS_UID annotations; allowed0/blocked1 map to the
actual atom enums1/2. The actual proto and generated native statslog encoding are
hashed/checked as oracles. Kernel loss totals are logged as real unsigned values.
An uncertain consume is never retried. Only genuine pre-consumption EAGAIN may
reschedule. Handler/reporter failures abort the exact current native owner and
stop event delivery; no duplicate consumer or synthetic event is introduced.
Statsd transport retains the platform's best-effort semantics.

loopback-worker-native-20261115-01 compiles all14 actual Java sources, including
the complete ConnectivityService and BpfNetMaps, against original A17 SDK
classpaths. It verifies unchanged native prerequisites and1243 projects/17 exact
patches before/after. No selected source/prebuilt/policy change is made.

loopback-worker-host-20261115-01 replays all previous suites, including87 event
transport Java cases, and passes36 new worker checks: one scheduled bounded batch,
no fake empty events, duplicate-start refusal, early genuine HOLD, reporter/handler
failures and terminal retirement, real constructor/report method statsd field/
annotation/enum order, single BpfNetMaps consumer across instances and the exact
ConnectivityService private/stock initialization condition.

Handler/StatsEvent/StatsLog and kernel/Binder/store boundaries are explicit host
fixtures. Actual service method bodies and actual production worker/report methods
execute; no full Android service startup or physical device execution is claimed.
Remaining gates include CLAT, final source/Soong/APEX/jarjar composition, explicit
kernel/policy selection, full ROM and installer/encryption/partition validation.
No flash-ready package exists.
