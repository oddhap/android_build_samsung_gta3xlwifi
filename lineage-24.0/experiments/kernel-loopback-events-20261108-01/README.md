# Socket-aware loopback permissions and genuine metrics

This isolated module applies selected Android17 cross-profile loopback permission
semantics to the supplied actual egress socket. It uses the already reviewed
referenced TCP/UDP peer lookup and immutable receiver creator UID; unknown receiver
never becomes UID0. System appIds and same profile pass; cross-profile checks use
the real current shared seven-bit permission image and the actual A17 force/full/
profiles bit expressions. Sender65534 is normalized by the egress caller; receiver
65534 remains literal. TCP checks SYN (including SYN+ACK), not established ACK;
other protocols and unknown/self receivers follow A17 exclusions. CLAT precedes
this check; tagged system DNS bypasses only later LNA, not loopback. Whole decision
is inside the existing RCU/HOLD drain domain. The optional UDP10ms performance
cache is omitted, so each eligible packet checks current real peer/permissions.

Selected checks and loopback metrics are READ_ONLY ENABLED (network-permission-
flags-20261106-02); no flag/property/BPF-ready/map is invented or disabled. Each
eligible real non-self peer decision produces allowed0/blocked1 with actual source/
receiver UID. A bounded512-record queue,100-key LRU and60s per-key rate limit
provide a genuine stream. Full queues count real loss without advancing report
expiry; LRU lookup recency is refreshed even when reserve fails, as in A17.
Additional sequence/boot-clock/loss metadata makes transport validation possible.
A17 payload constants are compiled into host assertions. No user injection or
metrics-disabling API exists.

GET_EVENTSc0206759 uses a32B native/compat transfer and40B event records, available
only to the existing root/init-CAP_NET_ADMIN/exclusive-file/TGID lease owner.
Metadata probes do not consume. Data reads require the probed head sequence.
Both user copies must succeed before consumption; the owner mutex serializes
readers while producers append under the queue lock. Sleeping copies hold no
producer spinlock. Feature128 means compiled check/event/read primitive only.

Host05 and the full build each pass1797 checks and98304 comparisons of all7-bit
permission pairs against actual A17 expressions. Tests compile actual module,
parser, real UID/LNA stores, actual egress and authenticated dispatch. Peer lookup
result/clock/copy/RCU/socket effects are fixtures; that lookup's original-reference
lifetime is separately tested. Cases includeIPv4/6 tuples, DNS/CLAT ordering,
UID normalization, actual overflow, bounded LRU (including expired-key reserve
failure), copy/allocation/auth faults and a producer appending during sleeping
consumer copies. Prior host01 failed C-fixture braces/foreignPID declaration;
host02 set real rather than effective UID for an auth test; host03/04 passed1183
cases before the explicit expired-key LRU correction and additional614 checks.
The final source/test is hash-bound by full-build reports.

kernel-loopback-events-build-20261108-01 exit0 at17:14:38UTC Nov8:
Imagec3194ba82cbaf32e3cab903d9cae0dff534fd823ee0e1fad715f7edaa6473f58,
configfac42 unchanged. Candidate60352/protected60331 tracked files and1243/17
Android before/after audits match. Gator118/KUTF43 imported versions match.
All lease/UID/LNA/parser/creator/peer and100 egress/51 receive regressions pass.
Full pipeline exit0; binaries stay on server, source/log/hash evidence collected.

loopback-policy-production/debug-20261108-01 append only exact ioctl6759. Strict
compile passes with5918/5881 original assertions/constraints,17 access queries,
actual device/genfs contexts and12 compiler oracles each: all6750..6759 granted,
outer674f/675a denied. No permissive domains, neverallow bypass or policy-input
selection. Pipeline completed17:25:57UTC. This remains isolated; no Android image
promotion, hardware packet validation, netd metrics worker/Binder delivery or
complete late ordinary/VPN/IIF/accounting/network startup is claimed.
