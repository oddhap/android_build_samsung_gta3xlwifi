# Ordered raw permission receiver

The actual Java PermissionBpfMap implementation accepts complete user/known-UID/
raw snapshots and serialized live updates. It preserves observed raw4 (INTERNET
only) separately from missing-known/no-permission identities. SDK UIDs inherit
exactly the pinned A17 Process/UserHandle projection. Removal applies across
users and SDK UIDs. Missing core coverage, unknown bits/users, conflicting SDK
rows and oversize images invalidate input rather than synthesize permissions.

One caller-supplied policy lock covers every callback and sink operation. Only
successful sink acceptance publishes the immutable permission input. Failure
clears it and invokes the invalidator synchronously. The backend sink must build
its full policy frame from the incoming snapshot argument, and must perform real
owner withdrawal/HOLD on failure. A buffered permission snapshot is not Ready.
This class does not query PackageManager or register itself as an observer.

Actual compilation against the original Connectivity classpaths plus the explicit
current permission API proposal passes; every original client class remains and
four collector classes are added. Full1243-project/17-patch audits pass. Host02
passes2258 cases including all1024 raw combinations, actual pinned UID function
bodies, SDK boundaries, immutable input, revocation/removal, invalid input, expanded
bounds, failure/cleanup and shared-lock concurrency. Binder, sink and sparse-map
fixtures do not establish Android observer or native/kernel execution.

Native01 checks the earlier receiver input; native02 also includes protection
against a cleanup callback rethrowing the exact original exception. Host01 stopped
because the test extractor missed @AppIdInt in UserHandle's declaration. Host02
lowers only that declaration annotation, retains the actual body and passes.
Attempt01's wrapper exit1 is preserved and does not invalidate the separate final
native02/host02 passing reports. Existing runners/outputs must never be overwritten.

Actual PermissionMonitor registration and BpfNetMaps routing, complete policy
buffering, Soong/APEX composition, statistics/event lifecycle, boot admission and
final ROM/installation gates remain. No selected source or device state changes.
