# Genuine bounded loopback event consume RPC

Inactive append-only RPC15 over stats-removal-20261115-02. The existing native
owner and authenticated lease consume actual kernel packet events; no second
session, BPF ring-buffer emulation, injected event or readiness flag is used.
Every call requires full UID1000 and the exact current session. Storage for the
maximum512-event reply is reserved before consumption. Wire schema is
[1,6,totalLost,count] followed by six words per event: senderUID,receiverUID,
result,boottimeNs,sequence,eventLost. Unsigned64 bits remain exact.

Actual Java StatsAccess serializes this stream independently of policy/factory
locks. It validates bounded lengths, full unsigned32 UID bits, allowed/blocked
results, nonzero contiguous sequences and monotonically increasing unsigned loss.
Cross-CPU timestamp reordering is permitted. Malformed/uncertain consumption
aborts the exact current owner; no consume syscall or uncertain RPC is retried.
Native pre-consumption EAGAIN exposes genuine HOLD, never an invented empty batch.

loopback-rpc-native-20261115-01 passes complete CFI Controllers/provider/qtag/
owner/lease/service netd and OEM DSO links, all12 Java sources,15 generated AIDL
ordinals and compatible API check, actual ARM32/64 UAPI and1243/17 before/after
audits. Kernel/prebuilts/policy/selected source are unchanged.

loopback-rpc-owner-host-20261115-02 passes26592 checks including63 new service/
owner/lease event checks: exact access checks before I/O, HOLD, real empty queue,
wire order/unsigned bits/loss, next sequence, uncertain consuming copy failure,
malformed event and quarantine. Kernel syscall/fatal dispatch are explicit host
boundaries; no real daemon/device was killed. Host01 initially enabled the new
successful-event fixture for an old test that intentionally expects ENOTTY;
host02 preserves that old boundary and enables event support only in new cases.

loopback-rpc-java-host-20261115-01 replays all prior suites (1467 client,61 poll,
327 consumer,13 factory,26 TrafficStats,7 cleanup,29 receipt,15 abort,62 durable
removal,18 admission/service), and passes87 new consume decoder/failure checks.

Android handler/statsd delivery is the next separate candidate, not validated by
this RPC proof. No physical Android execution or flash-ready ROM is claimed.
