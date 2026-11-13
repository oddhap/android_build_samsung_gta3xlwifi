# Actual postrouting interface DROP correction

An isolated exact delta on kernel-iface-stats-20261113-01 connects all three
existing IPv4, IPv6 and multicast postrouting output wrappers to a small
`gta3xlwifi_accounted_egress` entry point. The original socket/UID/tag/DNS/CLAT/
ordinary/IIF/LNA/loopback policy is unchanged. A nonzero policy result performs
the actual interface counter's unsigned egress UNDO before the caller consumes
the skb. Later fragmentation or downstream errors do not trigger a second UNDO.
The wrapper does not mutate or free the borrowed skb, clamp arithmetic, install
producer rules, or implement UID/tag accounting.

An outer RCU read section covers both the original decision and correction,
including the interval after the original policy's inner unlock. Consequently
HOLD/synchronize_net must drain the correction too. The private header preserves
a config-off fallback; the actual product retains its unchanged builtin QTAGUID
configuration. No UAPI, ioctl grant, capability bit or selected policy is changed.

The real counter module is byte-identical after removing only the new wrapper
and its includes. The wrapper and unchanged actual counters pass 251 host checks,
including 60 packet-flow comparisons using the actual pinned Android17 arithmetic,
all return classes, null/default interface, unsigned underflow, full-table loss,
and a real pthread reader/grace race after the simulated policy's inner unlock.
Policy decisions, kernel APIs and grace effects are fixtures; this is not device
execution. Host01 unused fixture declarations were removed; host02 passes.

The full isolated kernel Image compiles. Actual configured modules compile and
Gator 118/KUTF 43 import CRC checks pass. Config is unchanged. All 60360 candidate
and 60331 protected source hashes match before, after Image, after modules and at
finalization; Android 1243-project/17-patch audits pass throughout. Final artifact:
`kernel-iface-egress-final-20261113-01`, exit 0. Image SHA256:
`5a59bffd4306d9a1fca95d13101c2fb2143923125f96cb74623487de05e97c76`.
Config SHA256 remains
`fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea`.

Two test assumptions stopped intermediate jobs; their original exit1 logs are
retained, not relabeled as successful. Image-stage checking assumed one IPv6
machine call per source callback, but GCC duplicates that callback. The corrected
check proves COMPLETE normalized IPv4/IPv6 disassembly identity against the
previous built objects, with only the intended call-target substitution: two
IPv4 and two IPv6 relocations. The counter module calls the actual original policy.
The fresh build runner now uses this stronger comparison.

The module-resume job compiled and checked all modules, then incorrectly treated
Module.symvers as frozen. Module builds add 47 exports. The finalizer verifies
BOTH exact hash endpoints against the captured pre-module file and actual module
CRC report, reruns the strict checker, retains all 8433 original exports among
8480 final exports, and verifies EVERY other frozen resume input. The Image,
vmlinux, config, firmware and all source remain unchanged. It reruns source and
Android audits and checks the three selected prebuilt hashes. It does not waive
any hash or substitute source. The historical one-off complete-kernel.sh and
failed evidence are retained; finalize-iface-egress24.py records the validated
expected transition. No binary or signing material is published.

Legacy egress/consume-once 100, receive 51, owner 92, loopback 1797, ingress/context,
UID/LNA, primitive 49/786432 and prior source-oracle regressions pass. Legacy
context tests explicitly model counter effects; the dedicated test executes the
actual store/wrapper. Complete policy and runtime readiness are not claimed.

Producer-rule activation must be coupled with this correction. Actual Android
BandwidthController initialization/control, UID/tag/app/bank/counter-set accounting,
service IPC/Java integration, metrics delivery and startup remain. Existing
strict policy grants are unchanged. No selected kernel/vendor/DTBO or Android
source is promoted. Encryption/rollback/installer and final OTA gates remain;
there is no flash candidate and no on-device action was performed.
