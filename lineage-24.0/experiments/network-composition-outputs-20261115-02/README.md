# Actual selected Soong module build and output verification

network-composition-build-20261115-01 completes actual m -j12 netd iptables
libnetd_resolv libnetd_updatable service-connectivity services.permission, exit0.
Build time is21:02, including the first graph regeneration. Actual Soong, Make,
Native/AIDL/Java/Kotlin compilation, shared-library ABI checks, jarjar, R8 and
current system-server API checking pass. All1243 projects/20 exact patches pass
before/after source audits.

The verifier checks selected109 source hashes, the actual installed ARM64 netd/
iptables/netd-resolv/netd-updatable ELFs, the real post-R8 Connectivity DEX Binder
identities, all16 ordinals in the actual Soong-generated min31 Java AIDL library,
all ten extension registrations in the actual iptables registry, the permission
module JAR, and unchanged selected Image/vendor21-MTP/DTBO inputs.

Both used runtime Binder interfaces retain their native descriptors and class
names after R8. The entirely unused unsolicited listener is removed by R8; this
is recorded explicitly. Verifier01 incorrectly required dead-code retention;
02 requires every retained interface identity to match and permits removal only
of that wholly unused listener. No product/source change hid a protocol failure.

This is actual build/link/DEX evidence, not host emulation, Android service
execution or hardware testing. services.permission is the module JAR; a complete
ROM/services/APEX packaging build is still required. The kernel and strict policy
must still be explicitly selected and integrated, followed by full product,
installer/partition/encryption/rollback checks. No flash-ready ROM exists.
