# Explicit complete permission bootstrap

Compiles a caller-supplied immutable Android 17 permission snapshot before the
first accounting-owner publication. Conversion matches the actual pinned
PermissionMonitor method and both loopback flag states. User coverage and the
framework's explicit all-granted root/system rows are required, never invented.
Missing known UIDs get NoInternet. An observed INTERNET-only entry converts to
canonical zero but remains present, so it is not incorrectly denied. Repeated
known shared-package UIDs are accepted; ambiguous observed duplicates, unknown
bits/users and oversized frames fail without changing the output.

publishInitialPermissions requires the held accounting startup and an unpublished
owner. Other initial policy state is explicit and its permission field must be
empty. Incomplete/invalid frames leave the gate held; the existing transaction
publishes all four states only after real kernel commits. Kernel/protocol failure
withdraws everything. Original owner implementation bodies remain unchanged.

This does not collect users/packages/permission callbacks, establish snapshot
ordering, expose Binder/Java routing or claim global readiness. Those caller
contracts still need integration and validation. No source/policy/prebuilt
selection, hardware validation or flash candidate.
