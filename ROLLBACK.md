# Returning from ARM64 beta to the ARM32 release

The ARM64 beta writes hybrid vendor. The old ARM32 ZIP preserves vendor, so
**restore stock CWA1 vendor first**, then install the original signed ARM32 ZIP.
Keep the updated PIN-free TWRP. Do not boot Android between those two steps.

Follow the complete [installation and rollback instructions](INSTALL_ARM64.md).
Download the firmware-derived stock vendor and guarded restore helper from
[the ARM64 beta release](https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases/tag/lineage-21.0-arm64-beta-20261007).
The helper source is [tools/restore-stock-vendor.sh](tools/restore-stock-vendor.sh).
It verifies root, device, TWRP, regular input file, size, SHA-256, target partition,
unmounted vendor and full partition readback. It writes only vendor.

The original ROM is in [the ARM32 release](https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases/tag/lineage-21.0-20261005).
Its SHA-256 is `94110cab46fa1edf908914dfbcc3c910ec5e5e16f306a810e13e673d3d5b597b`.

The migration rollback was physically tested on 2026-10-07 with full vendor
readback, successful ARM32 OTA, ARM32 GLES graphics, SELinux Enforcing and
preserved PIN/CE storage, without formatting userdata or writing EFS.
[Physical rollback report](reports/arm64/baseline-rollback-check.json).
The packaged restore helper has separate host refusal checks; it was not
independently flashed during publication. Private device backups and logs
are not required by the public procedure and are not distributed.
