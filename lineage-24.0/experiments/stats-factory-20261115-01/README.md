# Durable actual NetworkStatsFactory routing

Inactive candidate stats-consumer24-20261115-02, over policy-fatal and framework-policy.
Selected source/prebuilts/policy remain unchanged. No flash-ready package exists.

The private factory captures the existing shared native policy-session handle
before its persistent-data lock. The owning NetworkStatsService supplies its
actual selected protected statistics directory. A complete versioned consumer
payload persists raw/adjusted cumulative NetworkStats, distinct UID tags,
stacked interfaces and active VPN metadata before frozen-bank ACK. Explicit
metadata amendments retain the last genuine native receipt through UID cleanup.
Replaying accepted state never adds the same bank again.

Frozen records resolve real kernel interface-name history and duplicate tagged
traffic into tag0 as the pinned A17 BpfNetworkStats.cpp does. The unchanged A17
NetworkStats implementations perform464xlat then VPN migration/debug filtering.
Grouping/sums check counter range,464xlat checks exact header arithmetic, and VPN
transient aggregation has explicit conservative signed-counter headroom.
Unsupported ranges, missing names, real loss, oversized/corrupt state and failed
I/O propagate errors without ACK or fabricated counters. Summary uses the real
nonconsuming interface table. Metadata changes are durable before publication.

Validation:
- stats-consumer-native01: five actual SDK sources and1243/17 audits.
- stats-consumer-host03: actual unmodified NetworkStats/UnderlyingNetworkInfo and
  pinned VPN arithmetic;1467 prior client cases,61 prior poll flows,322 new checks.
- stats-factory-native02: eleven actual Java sources including full factory,
  service, BpfNetMaps, PermissionMonitor and shared backend compile against the
  actual Connectivity and service-t module classpaths;1243/17 audits pass.
- stats-factory-host02:1467 client cases,61 poll flows,326 consumer assertions and
  12 actual factory assertions pass. Only JNI library loading and Android API,
  Binder/kernel/store boundaries are fixtures. Factory runs with a real client
  lock held elsewhere, persists via actual temp-file sync/rename, preserves UID
  cleanup on same-boot reconstruction, and never invokes the old private JNI.

Host01 for the factory label exercises the326 consumer assertions only; it does
not claim actual factory coverage. Earlier incomplete host fixture attempts
and the first service SDK classpath failure remain in server artifacts. The
service-t classpath was obtained from its real Ninja command without executing
that command or touching TOP outputs.

Remaining: NetworkStatsService map/listener initialization, TrafficStats public
reads, kernel UID/socket cleanup, loopback event delivery, CLAT raw-socket
lifecycle, final source/Soong/APEX composition, full product and installation
checks. The service still has BPF initialization consumers; this isolated source
set is not a usable networking runtime yet.
