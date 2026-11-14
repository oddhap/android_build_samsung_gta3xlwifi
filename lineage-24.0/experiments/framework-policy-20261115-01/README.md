# Actual framework permission and policy routing

BpfNetMaps now has an explicit product-gated branch before generic initialization
opens BPF maps. The actual system-server SDK exports SystemProperties.getBoolean;
no hidden-API assumption or fake map is introduced. Supported actual process flags
are required rather than changed. A single shared backend/token/lock handles all
instances. Unsupported migration/propagation/beta/L4S modes fail explicitly.

PermissionMonitor directly registers the actual raw receiver with its pinned
permission list and actual loopback mode. It bypasses the old canonical callback
wrapper on this private path, preserving stock code. Complete same-epoch identity
callbacks and live changes reach the owner through real Binder frame transport.

The backend buffers early policy while the owner remains held. Complete permission
input triggers a full frame of actual policy and runtime state. Ordinary/metered
chains, data saver, IIF/lockdown, ingress discard, both LNA tables and legacy blocked
UIDs route to the shared owner. Queries require the exact current native committed
generation before reading cached values. Errors withdraw publication/close the
token. Observed INTERNET-only raw4 remains distinct from missing-known NoInternet.
Actual A17 Struct classes encode LNA keys; key bytes retain their native field
order inside the explicitly network-word-encoded transport.

Both native01/02 compile the actual changed BpfNetMaps, PermissionMonitor, backend,
client and receiver against original Connectivity classpaths and the explicit
permission API proposal. Full1243-project/17-patch audits pass. Version02 validates
buffered-state capacities early, rejects unassigned discard addresses and formats
the new backend with the actual AOSP formatter. Class/interface typechecking is
not a full Soong/APEX module build.

Host02 executes actual backend/client/receiver, actual A17 BpfNetMapsUtils oracle,
Struct/key/IPv4-mapping classes and exact generated-interface fixtures. It passes
219573 checks and emits2111 complete frames. The actual native parser and policy/
permission/LNA value compilers accept every frame and pass270348 independent
comparisons. Both loopback modes cover all1024 raw combinations. Tests cover early
buffering, packet-rule values, UID/core/SDK behavior, capacities, interfaces/LPM,
removal, failure withdrawal and generation mismatch. Host01 only lacked supporting
host classes and used an ambiguous reflection import; the corrected host02 keeps
production source unchanged. Binder/map/transport fixtures are explicitly host
fixtures, not device execution.

Remaining: native DNS still needs this sole owner, statistics/events/CLAT lifecycle,
actual private boot admission/oneshot, restart/resnapshot checks and Soong/APEX
source/dependency composition. Legacy permission-writer modes and packet-stat SWAP
remain explicit unsupported errors rather than touching BPF maps. BPF-map metrics
return PULL_SKIP instead of invented counts. No global networking Ready, selected
kernel/vendor/policy/source promotion, ROM or device execution is claimed.
