# Atomic canonical-UID socket tagging

The sole policy owner checks full-UID UpdateDeviceStats permissions, the exact
A17 appId0/1000/1051 exemptions, literal CLAT denial and actual active-statistics
budgets before invoking the trusted transport. All permission reads, counter
snapshots and tag/untag I/O share its transaction mutex. A permission update cannot
race a tag operation. Limits are the pinned A17 strict >500 perUID/>4500 total
row counts, not tag/socket counts. Actual UID migration is required by the future
Java bridge; no flag is fabricated or silently converted.

SocketTagger is an internal native dependency, never an object accepted from a
Binder caller. QtaguidTransport keeps real socket-owned sessions, pinned TCP/UDP
FDs and actual proc/sysfs/7151 I/O. It exposes explicit stop/connected state;
passive/inaccessible transport closes the session and does not automatically
recover. Ordinary invalid FD/family/protocol or a connected command rejection
returns its error without letting app requests shut down the network. Session
loss or positive protocol results quarantine the owner and hold the packet gate.
Connected means only an open transport, not networking readiness.

The actual owner passes 22,697 assertions, including 7,680 comparisons with the
pinned actual A17 permission and charge-UID guard bodies. All128 masks, twelve
real UIDs, five charged UIDs, budget boundaries, transport errors, stats faults
and actual thread serialization are covered with explicit kernel/rule fixtures.
The later held-provider candidate replays all of these and compiles the real
transport. No hardware sockets are tagged by this owner test.
