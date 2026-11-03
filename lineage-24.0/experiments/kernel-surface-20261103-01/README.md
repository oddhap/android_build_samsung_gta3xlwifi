# Android 17 policy versus legacy kernel declaration surface

Read-only investigation. No kernel source, configuration, Image or device is
changed, and no enforcement or boot approval is implied.

`policy-classes.json` is extracted from the actual built Android17 userdebug
platform CIL. It includes all 108 class declarations, resolves inherited common
permissions and records the source digest and six active policy capabilities.
The original classmap matches both the preserved kernel source and manifest
kernel byte-for-byte. The Android17 common-kernel reference is revision-locked.

The audit compiles the actual C classmap string tables on the host with ASan/
UBSan and compares names/permissions. Intersecting with the modern kernel table
keeps userspace SELinux classes separate. The original kernel lacks 42 of these
class declarations and permissions in 39 existing classes. The isolated candidate
adds process2 and the four nlmsg permissions but still has substantial gaps.

These counts are review inputs, not counts of exploitable defects or features
that must all be enabled. BPF syscall, user namespaces, userfaultfd, fanotify,
SCTP and DCCP are disabled in the preserved config; perf events are enabled.
Declaration presence also does not prove that a kernel hook checks it.

Priorities include the active extended-socket capability, mmap `map` checks,
getrlimit, enabled perf-event mediation, coherent netlink decisions during policy
reload, and the complete existing NNP/FunctionFS graph. Missing functionality
must be backported or kept unavailable through a reviewed compatible design.
Adding class names alone cannot establish enforcement or justify removing the
netlink capability rejection. Whole-kernel compile, current policy validation,
Android runtime and hardware checks remain separate requirements.

The conditional Samsung ALWAYS_ENFORCE fixture tests are not proof that the
preserved Image was compiled with that macro. This config does not list it;
compile-time definitions and actual enforcement must be audited separately.

Reproduce with `tools/audit-kernel-policy-surface.py`, supplying the original and
pinned reference headers, extracted policy JSON, preserved config and a fresh
output path. An optional candidate header compares the isolated declaration
table; it does not promote that candidate or test its hooks.
