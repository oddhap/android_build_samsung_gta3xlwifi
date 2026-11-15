# Privileged CLAT raw FD and actual Android coordinator

Inactive delta over loopback-worker-20261115-01. The actual existing provider and
qtaguid session accept one dedicated RPC16, tagClatSocket(session,PFD), requiring
full UID1000/current session. A pinned duplicate must be AF_INET6, IPPROTO_RAW,
SOCK_RAW before the sole tag0/UID1029 command is written. Ordinary UID1029 tagging
remains denied, and ordinary sockets retain TCP/UDP validation and existing
budgets. No second session, invented cookie, BPF map or readiness flag is used.

Actual BpfNetMaps captures its existing owner only. Actual ClatCoordinator skips
BPF maps/offload/cookie solely on this private route, tags the real raw FD before
starting userspace clatd, and closes all parent FDs in its existing finally flow.
The real child retains the spawned socket FD; stopClatd waits for its exit. Real
kernel final-release untag retires the socket-owned tag. The tracker has an
explicit nullable cookie and private diagnostics identify socket lifetime. Stock
map/cookie behavior is preserved. Private startup failures after a known spawned
PID attempt child cleanup and retain cleanup errors as suppressed exceptions.

Validation:

- clat-rpc-native01: full CFI Controllers/provider/qtag/owner/lease/service netd
  and OEM DSO;14 actual Java sources;16 append-only AIDL ordinals/API compatible;
  ARM32/64 UAPI and1243 projects/17 exact patches audited before/after.
- clat-transport-host01:2582 checks,242 new. Real socket/dup/FD-reuse behavior;
  raw type/protocol getsockopt and driver I/O are explicit fixtures. Exact1029/
  tag0 serialization, rejection before write and uncertain short-write retirement.
- clat-owner-host01:26622 checks,29 new. Actual service/owner with explicit PFD/
  provider/kernel boundaries: fullUID/session/HOLD, ordinary1029 denial, and
  disconnected/positive-result quarantine.
- clat-coordinator-native02:15 complete actual Java sources, including real
  ClatCoordinator and ConnectivityService, compile against original Soong Android
  core system modules/SDK classpaths. Native16 prerequisites are unchanged;
  1243/17 before/after audits pass. Attempt01 identified missing Android java.net
  extensions in the prior host-JDK compilation harness; actual source was not
  weakened. The corrected harness binds the real --system directory files.
- clat-java-host03 replays all prior suites, including87 event and36 worker cases,
  and passes56 CLAT cases. Actual full coordinator source executes with one
  explicit Android InetAddress numeric-parser builtin boundary for host JDK.
  Actual Struct/key sources execute; FD/Binder/driver/process/Android APIs are
  explicit fixtures. Tests cover constructor routing, successful startup/stop,
  ten startup fault points, uncertain tagging/no replay, parent descriptor close,
  no private map/cookie/offload call, prefix bounds and preserved stock cookie flow.
- clat-kernel-host03:46245 actual extracted kernel-function checks,291 new.
  Tag0/UID1029 IPv6 tags survive daemon/session turnover and retire on explicit
  final-release boundary. Actual INET/INET6 release hooks are checked, and all
  60366 built source hashes are verified before/after. This is not kernel execution.
- Production/debug compiled strict policies already allow required netd borrowed
  FD use/raw-socket getsockopt and clatd inherited FD read/write. Queries preserve
  the existing clatd getsockopt denial, which the current clatd sources do not use.
  No policy input, grant, assertion, neverallow or enforcement setting is changed.

Host fixture attempts01/02 respectively lacked adoptFd and tried to execute
non-executable hjar key signatures;03 uses complete actual key sources. Kernel
check attempts01/02 exposed symlink hash semantics;03 matches the original audit's
Path.readlink().as_posix() hashing, including trailing-slash normalization, without
changing any kernel source or expected hash. Failed outputs remain on the server.

No selected source/kernel/vendor/policy promotion, physical device execution or
flash-ready package is claimed. Final Soong/APEX/jarjar composition, explicit
snapshot/kernel/policy selection, full ROM and installation/encryption/partition
checks remain.
