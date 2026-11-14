# Complete permission frames on identity changes

Registered consumers now receive a same-state complete replacement snapshot when
AccessState's user/installed-UID identities change, before that mutation's UID
deltas. An added zero-permission UID need not generate a permission-flag event;
this path includes it through real installed-package metadata. Snapshots never
invent an INTERNET grant. Root/system rows still come from the original raw
permission helper. Normal unchanged-identity permission updates retain deltas.

Each consumer has an independent sorted identity epoch, updated only after its
successful callback. Registering another consumer cannot conceal an older
consumer's pending change. Callback arrays are cloned to isolate cache state.
Unregister takes the same state lock, fences callbacks and removes both caches.
The existing default callback still delegates actual raw updates to old consumers.
No additional interface method or signature change is introduced by this delta.

Actual full71-source Kotlin compilation preserves all155 original classes and
compiler flags. Complete1243-project/17-patch audits pass. Actual metalava source
API generation and full server compatibility pass, including the removed-method
negative control. Host tests pass96 cases, including all prior81 ordering cases,
zero-permission/shared/APEX/installed UID metadata, new/removed users, independent
consumer epochs, mutated callback arrays, failed epoch retry, old consumers and
10 unregister fences. Fixtures do not establish Android service execution.

This reacts to AccessState mutations; it is not proof that every PackageManager
installation path refreshes that state. In particular, current DEFAULT install
parameters return early in PermissionService.onPackageInstalled. Normal existing-
package installs use a built parameter object and update AccessState before app
data preparation; system-package/default paths require a separate explicit audit
and, where needed, an identity-only state refresh preserving old permission logic.
Java receiver/SDK expansion and BpfNetMaps routing remain unimplemented. No source,
policy, prebuilt or device state is selected; this is not a networking Ready signal.
