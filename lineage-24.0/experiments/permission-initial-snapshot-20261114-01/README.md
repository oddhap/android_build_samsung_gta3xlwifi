# Ordered initial framework permission snapshot

This inactive frameworks/base proposal orders registration, raw initial permissions,
installed-package UID/user metadata and the initial callback under the same state
lock as permission mutations and their synchronous callbacks. It prevents an old
initial grant from overwriting a newer revocation. Callback failure unregisters
that consumer; duplicate registration is checked inside the serialized section.
Metadata comes from the same immutable state, including installed shared UIDs and
packages with no permissions, excluding APEX entries. No grants are invented.

The new Java default callback delegates to the existing method for old consumers.
The explicit server API signature adds only that default method. Android's actual
metalava generates the exact old/new signatures and accepts full server API
compatibility. A removed-method negative control is rejected without a baseline,
ignored diagnostic or compatibility bypass.

Actual complete 71-source Kotlin compilation with the original 64 classpath jars,
compiler flags and ABI plugin passes. The exact original 155-class inventory is
preserved. All outputs remain outside the selected checkout. Complete 1,243-project/
17-patch source audits pass before and after compilation.

The host fixture executes the actual registration/lock bodies and Java default
interface: 81 cases pass, reproducing the old revocation overwrite, 50 ordered
races, 25 duplicate-registration races, same-epoch metadata, callback-failure
cleanup and old consumer compatibility. This is not Android/Binder execution.
The first compiler checker incorrectly expected more than 200 classes; it was
replaced with exact original class inventory equality. First host attempt missed
a fixture collection extension. First API attempt used a source path without the
Java package suffix. These failed attempts and successful retries are preserved.

No framework/netd IPC client, complete policy frame, network readiness or device
execution is implied. Apply only as an explicit reviewed source/API patch alongside
the eventual bridge; nothing here is automatically selected or flash ready.
