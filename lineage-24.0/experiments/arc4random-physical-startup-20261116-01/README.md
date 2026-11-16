# Physical recovery startup regression

The previous static ARM32 helper aborted before main because MADV_WIPEONFORK
is unsupported on the actual preserved Linux4.4 TWRP. No ROM image was written.
Snapshot04 uses genuine blocking kernel entropy on this kernel, without inherited
userspace RNG state. The newly built helper passed its real read-only recovery
identity/header check. The ARM64 updater reached its ordinary invalid-argument
exit, rather than aborting in its constructor. No ZIP was passed to updater.
SELinux remained Enforcing. This establishes startup compatibility for these
executables only. It is not Android17 boot/network/FBE validation.

The report records actual binary hashes. Device serials, partition backups,
private access material and executable images are deliberately not published.
