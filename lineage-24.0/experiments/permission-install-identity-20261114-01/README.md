# Identity-only refresh for DEFAULT installation callbacks

The original DEFAULT install-parameter branch deliberately skips permission-policy
changes, including restricted-permission exemption clearing. It now refreshes
only actual external package/disabled/known-package state before returning. The
normal mutation publication invokes the complete identity observer. No permission
grant, flag or exemption is changed. Non-DEFAULT permission logic is byte-identical.
PackageManager snapshots are read before the permission-state lock. A cold-state
guard avoids accessing uninitialized fields; normal initialization takes its own
complete PackageManager snapshot before any consumer registration.

Actual complete71-source Kotlin compilation preserves155 classes and original
flags. Full1243-project/17-patch audits and actual metalava generation/compatibility/
removed-method negative control pass. The actual helper and DEFAULT branch pass13
host fixture cases covering cold state, current identities, old grants/exemptions,
query ordering and failed getters. All96 prior lifecycle/concurrency cases replay.
The combined validation exits0. This is not PackageManager or Android boot execution.

The proposal depends on permission-lifecycle-20261114-01 and is inactive. Actual
Java receiver/SDK expansion, BpfNetMaps routing, Soong/APEX composition and runtime
boot/network admission remain, followed by installation gates. No selected source,
prebuilt, policy or tablet state changes; no flash candidate is claimed.
