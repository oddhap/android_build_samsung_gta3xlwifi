# UID permission image transport primitive

Incremental proposal over netpolicy-lease-transport-20261106-01, with the exact
new kernel UAPI header. Extends the existing same exclusive file lease; no FD is
exposed. Start/hold/release behavior and original65 regressions remain unchanged.

Reads verify primitive feature bits, bounded/versioned metadata, exact-revision
payload and canonical sorted/nonzero seven-bit entries before changing caller
output. Revision0 is reported honestly as uninitialized, never as ready.
Replacements validate/allocate buffers before I/O, require held state and exact
previous revision, SET the complete next image and verify exact metadata/data
and held state before returning the new revision. No allocation occurs after SET.
The method never releases the gate. Kernel/protocol uncertainty closes the lease;
ambiguous writes are not reported as old or committed state. EINTR SET retries
use the kernel's identical-revision idempotency. Invalid local input preserves
existing state without I/O. This primitive does not implement combined rule/image
rollback or permit publishing a complete callback/network readiness value.

Host90 fault/protocol cases and original65 transport regressions pass with fatal
UBSan and syscall fixtures, including16 concurrent coherent readers, copy/readback
errors, malformed/oversized images, stale revisions, commit-then-error, interrupted
write retry, held-state loss, empty and65536-entry images. No device syscall occurs.

Actual Android17 netd ARM64 CFI compile/link-to-object passes with original flags,
source audits1243 projects/17 patches before and after, and unchanged production
objects. Actual existing keyutils ARM32/ARM64 Soong commands independently compile
wire layout assertions, then link to real ARM ELF objects: transfer24 bytes,
entries8 bytes, offsets8/16, SET0x40186755, GET0xc0186756 in both architectures.
This is object/ABI evidence, not complete netd linking or kernel execution.

All new kernel/image/policy/backend inputs remain isolated. Next: one serialized
permission/rule transaction, full authoritative provider and mandatory packet
LNA/loopback/real metrics/VPN/IIF/DNS/CLAT/startup. No flash candidate exists.
