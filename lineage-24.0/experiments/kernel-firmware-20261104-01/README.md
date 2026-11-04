# Isolated firmware load mediation

The preserved kernel enables firmware loading and its user-helper fallback. Its
existing kernel_fw_from_file LSM dispatch had no registered SELinux hook. This
candidate appends the real system firmware_load permission and registers a hook
at that existing dispatch. Direct loads check FD use for a different opener and
system firmware_load against the inode SID with the legacy PATH audit. The
user-helper NULL-file completion checks the caller against itself. Existing
module-load mediation, loader bodies, common LSM dispatch and subsequent IMA
call remain unchanged. Built-in firmware and cached data are not new hook sites.
This uses the pinned Android17 load-from-file decision through the old kernel
API; it does not claim to backport every modern kernel_read_file category.

Mac ASan/UBSan actual-body fixtures pass 1,024 firmware LSM/FD/IMA, 6,144 full
direct-loader and 1,024 full user-helper completion scenarios. They compile the
actual LSM macro, head initialization, registration and helper/loader bodies.
Filesystem, allocation, IMA/AVC, mapping, list/locking and completion backends are
sequential fixtures; no live firmware, device or concurrency test is claimed.
The original zero-byte kernel_read return behavior is preserved, not repaired
or counted as published firmware. Existing class/permission IDs remain exact.

Complete kernel compilation and Linux fixture checks finish exit 0. Mac/Linux
results, runner/extractor and input hashes match. Full 60,331-file candidate and
protected-source audits pass, with exact config/firmware. All 8,408 vmlinux
export CRCs match the perf parent; its 1,104 changes from the original remain.
The parent symbol file also contains module exports from subsequent module
work, so whole-file hashes differ. No live ABI approval is implied. Image SHA256:
`ad5a7b3ebede6b8b15ccf885e9fc5479f96905511227de85a468534bce17744d`. No Android
prebuilt promotion or installer approval. Capability9 rejection, strict vendor
policy, networking, module ABI and FBE/installer/rollback gates remain open.
