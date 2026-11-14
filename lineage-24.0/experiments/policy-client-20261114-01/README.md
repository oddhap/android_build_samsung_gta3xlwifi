# Explicit complete-snapshot Java transport lifecycle

The real Java client looks up the append-only OEM endpoint through INetd18,
retains a token before a separate idempotent session handshake, clones every
complete-frame section and sends bounded4096-word chunks. It queries the actual
committed generation and commits exactly once. An exception never triggers an
automatic commit retry. Publication failure attempts real native HOLD/retirement;
a fresh client and freshly collected complete state are required. Failed cleanup
retains its token/death link for explicit retry. A lost close reply can be retired
on ESTALE without closing another token. A connection is not networking Ready.

Two append-only private RPCs read the owner's exact generation and explicitly
retire a token, including an interrupted OPEN whose session reply was lost.
All seven RPCs require full UID1000. Retirement withdraws publication/HOLDs before
unlinking the client, including queued-death protection. Actual generation access
uses the owner's mutex; stopped/quarantined owners return ENOTCONN.

Native03 passes actual AIDL old/new private and OEM compatibility, C++/Java
generation, actual Java client typechecking against the original Connectivity
module classpaths, complete netd/OEM DSO CFI linking, unchanged dependencies and
1243-project/17-patch audits. Native01's classpath lacked INetd/OsConstants;
native02 fixes the tool classpath. Final native03 also checks the final Java
publication-error retirement change. Earlier Java input is preserved separately.

The actual owner/service host fixture passes25,856 assertions, including all
seven RPC identities, generation and token retirement, simultaneous frame starts
and offsets,10 commit-vs-death races and every prior frame/provider check.
The actual Java client passes580 assertions with declarations extracted verbatim
from actual generated AIDL. Tests cover65536 UIDs, chunk bounds, immutable inputs,
concurrent frame serialization, death, interrupted OPEN/CLOSE/COMMIT, failed
retirement retry and publication-error withdrawal. Binder/driver fixtures are
explicit: these results are not actual Android IPC or packet execution.

No BpfNetMaps/PermissionMonitor collection or routing is implemented here. Mainline
Soong dependency/source composition, complete state collection/SDK UID expansion,
boot admission, CLAT/stats/events and final installation gates remain. No selected
source, policy, prebuilt or device state is changed. This is not a flash candidate.
