# Actual statistics RPCs and lock-independent Java access

This inactive delta appends four private RPCs after the original seven: genuine
non-consuming statistics reads, explicit SWAP, explicit ACK and counterset edits.
Every RPC requires full UID1000 and the active framework session. All controls
use the sole owner/mutex/lease. An uncertain operation is not retried; underlying
kernel/protocol errors quarantine the owner. No read automatically clears rows.
Final UID deletion and socket-tag cleanup are deliberately not exposed here.

All returned arrays are bounded. AIDL long retains exact unsigned64 counter bits.
readStats kind0 returns15 words: schema1,kind,activeBank,activeEpoch,pendingMask,
bankCount0/1,bankEpoch0/1,bankLoss0/1,appCount,countersetCount,appLoss,totalLoss.
Kind1 returns schema1,kind,bank,epoch,sequence,loss,count, followed by count rows of
uid,tag,counterset,ifindex,rxPackets,rxBytes,txPackets,txBytes (max5000).
Kinds2/3 return schema1,kind,sequence,loss,count, then uid/ifindex plus those four
counters (max10000 apps/1000 interfaces). Maximum payload is400040 bytes; failed
Binder delivery consumes nothing. SWAP returns activeBank,activeEpoch,frozenBank,
frozenEpoch. Caller persistence/boot-epoch deduplication MUST precede explicit ACK.

Gta3xlwifiStatsAccess captures an existing real session before the factory's data
lock. Its read/decode/error paths never acquire the Java client/policy locks.
It validates schemas, identities, capacities, keys and strict ordering, retains
actual loss/sequence/counter bits, and copies mutable arrays. Malformed/uncertain
RPC results atomically invalidate the parent client and close its real token.
A genuine early HOLD/EAGAIN read is unavailable data and leaves the producer
alive for initial publication. Reported loss is not converted into complete zero
counters. This is a transport/decoder, not the completed Android polling pipeline.

Native02 passes actual append-only AIDL API checking and all11 ordinal checks,
generated C++/Java, actual CFI service/OEM/netd links and1243/17 source audits.
Native01 only used an incomplete Java classpath; original runner/logs are kept.
Host02 passes26184 actual owner/service checks, including5000/10000 row maxima,
unsigned64 bits, per-call authorization/session checking, no mutation replay and
failure quarantine (host01 passes26180 before the boundary additions).

Java-native02 compiles both final actual Java clients against original Connectivity
classpaths, binds all unchanged native sources exactly to native02, and passes
1243/17 audits. Java-native01 stopped in the runner's path hashing before any
compile/audit; its classpath string was mistakenly treated as one filesystem path.
Java-host01 passes1467 checks, replaying prior policy lifecycle/serialization and
covering10000/5000/1000 row boundaries, malformed/lossy data, early HOLD, failure
withdrawal, immutable results and both successful/failed stats calls while another
thread holds the actual client lock. Binder/ioctl/rule effects remain explicit
host fixtures, not actual Android IPC or packet/device execution.

Prerequisites: private-boot-20261115-01 and framework-policy-20261115-01.
Final full candidate is stats-rpc24-20261115-03; native sources are byte-identical
to01/02. Selected Android source/kernel/vendor/policy/prebuilts remain unchanged.
Still required: actual factory/TrafficStats consumers, real interface-name history,
boot identity and persistent acceptance/deduplication before ACK, counterset/UID
removal lifecycle, loopback events, privileged CLAT, Soong/APEX source composition,
strict policy integration, full ROM and installation validation. No flash-ready
package or networking readiness is claimed.
