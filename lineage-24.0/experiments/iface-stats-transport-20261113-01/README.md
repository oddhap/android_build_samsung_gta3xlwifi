# Interface snapshot transport through the policy owner

This exact delta on socket-projection-20261113-01 adds a non-consuming real
interface-counter snapshot reader. The same policy lease and mutex serialize
reads, state changes and event consumption. A transport/protocol/capability error
closes the lease and withdraws all four published policy values. No FD is exposed.
The primitive capability is distinct from accounting activation or global readiness.

One call provides capacity 1000 and takes one consistent kernel snapshot. EINTR
retries reset the entire request. Version, count, pointer, reserved fields, index
bounds, sorting and uniqueness are validated before publishing the result. Actual
loss and the opaque modulo-2^64 sequence are returned unchanged; sequence wrap is
not falsely rejected. Unsigned counter values are preserved. No map is fabricated.

The direct host transport passes 25 cases, including retry after a modified reply,
wire faults, errors, capacity, real loss values and sequence wrap. The full owner
passes 994 cases, including withdrawal when the genuine counter primitive is
missing, its prior publication/fault/concurrency checks and the strict firewall
cutoff before LNA/UID image SET. Syscalls and firewall tables are fixtures.
Projection host01 exposed a missing method declaration; it was added and host02
passes. Failed evidence is retained.

Native02 compiles all twelve actual sources using Android17 ARM64 netd LTO/CFI
commands and partially links the ELF. Both real ARM32 and ARM64 commands validate
entry40, transfer32 and match8 layouts and GET 0xc020675a. All seven private UAPI
headers match the built isolated kernel. Before/after audits pass for 1243 Android
projects and 17 exact patches. Native01 also compiled successfully, but its report
accidentally recorded the last wire-test link command in the primary link field.
Its original compiler is retained and hash-bound; native02 repeats compilation
with separate reporting variables. No candidate C/C++ changed between native jobs.

Strict production/debug policy extensions add only netd ioctl 0x675a to the
explicitly selected prior loopback-policy inputs. All 5918/5881 assertion and
constraint records are preserved. Each flavor passes strict compilation, 17
actual access/label checks and 13 compiler oracle probes: eleven intended codes
are granted and both neighboring codes denied. No permissive domains or disabled
neverallows are introduced. These policy inputs are not automatically selected.

This does not activate producer rules, wire DROP UNDO, implement UID/tag/bank
accounting, publish complete networking, or integrate platform services/startup.
The existing selected Android source, objects and kernel/vendor/DTBO are unchanged.
No installation candidate or on-device runtime claim is made.
