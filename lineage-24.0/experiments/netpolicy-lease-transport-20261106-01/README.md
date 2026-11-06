# Isolated real-kernel packet-barrier lease transport

This component opens the real private misc device, not a property or cached
readiness flag. It checks the root-owned regular sysfs device-ID file on sysfs,
bounded exact major/minor text, the character-device identity, root ownership
and exact mode0400. It requires the private ABI version and initially held state.
The isolated ueventd0400 proposal must be integrated before native use.

HOLD/RELEASE require the expected acknowledgement and an actual state readback.
An unexpected/error response closes the owned descriptor, causing the private
kernel driver to hold the barrier again. This also covers an ioctl error after
a committed change. No descriptor is exposed, methods are mutex serialized and
close is never retried on Linux EINTR. Caller output is preserved on read errors.

65 host cases with fatal UBSan test actual C++ code and wrapped syscalls, covering
identity/schema/ownership/mode, absent ABI, syscall failures and interruption,
unexpected acknowledgements/state, close failure and contended operations.
Device/sysfs/ioctl effects remain fixtures; no real device/network is accessed.
The native source compiles with actual Android17 netd ARM64 CFI flags and links
a real relocatable ARM64 object. Full 1,243-project/17-patch audits pass before
and after. This is not a complete linked netd daemon, real packet/FD test or
backend readiness. The owner must verify guard/DROP attachments in both families
before releasing the barrier; this transport does not install or verify rules.
