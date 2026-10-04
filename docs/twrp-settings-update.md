# SM-T510 TWRP settings/version update, 2026-10-04

TWRP displays `3.7.1_12` without a device/test suffix. Recovery preferences
use `/cache/TWRP/.twrps` while internal FBE media is locked. Corrected the folder
variable and missing filename separator. The read-only prompt checkbox remains
visible when separate preference storage is mounted and writable. Preferences
are reset if cache is erased. Backup/media paths and Android encryption remain
unchanged; no user credential is stored in TWRP's persistent preferences.

Physical tests: RECOVERY partition size verified before writing; image transfer
and exact-length partition readback SHA-256 match. Root ADB verifies packed
recovery executable. Normal TWRP recovery reboot changed the kernel boot ID,
loaded the saved preferences, retained `tw_never_show_system_ro_page=1` and
`tw_mount_system_ro=0`, and started page `main2`. User confirmed the menu.
An additional correction refuses to treat an empty FBE user list after failed
DE-key loading as successfully decrypted. Current state is encrypted and locked.

Installed image: `a4f888dbd7d409669d66de66485b2c2c7aa9e5357eaf8c3c93b2df32b187c8f1`.
No data format, ROM replacement or encryption downgrade was performed.
This is a recovery preference/UI fix, not Samsung FBE decryption support.
The user has subsequently requested porting decryption; that work is separate.
