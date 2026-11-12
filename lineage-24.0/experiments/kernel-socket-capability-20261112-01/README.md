# Registered dual-stack private-table capability

Adds UID_FEATURES bit256 only for successfully registered IPv4+IPv6 private
socket tables with the exact-skb UID snapshot prerequisite. The acquire/release
registration flag is real, and an IPv4-only configuration reports zero. This
primitive does not assert packet attachment, installed policy or backend readiness.
No ioctl number/layout, SELinux grant, global NF hook or selected prebuilt changes.

65 actual-C host assertions and864 grammar comparisons pass, including late init
failure/unwind and registration state, plus a separate IPv4-only compilation.
Legacy UID/LNA/loopback harnesses explicitly stub this unrelated registration
primitive to zero; the dedicated test compiles the actual function. The initial
build attempt stopped in the legacy loopback fixture's missing declaration; its
full after-audits and failure evidence are retained. Attempt02 uses a fresh clone
and output, rather than modifying an active/existing build.

kernel-socket-capability-build-20261112-02 exit0:
Image95484fefe086ab6eaa9b9e602e6f13fac8b28c5070f154c94ff6874ab263bc1e;
configfac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea
unchanged. Full kernel/modules, Gator118/KUTF43 imported versions,60355 candidate/
60331 protected kernel files and1243 Android projects/17 exact patches pass.
The following six-source native CFI job also passed; the sequential pipeline
finished exit0 at19:25:49UTC November12. No hardware or complete networking proof.
