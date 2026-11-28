# LineageOS 21 for SM-T510 — ARM64

Native **ARM64 Android 14** with **ARM32 app support**, for Samsung Galaxy Tab A
10.1 (2019), **SM-T510 / gta3xlwifi only**. Unofficial, signed with the existing
release keys, SELinux Enforcing and file-based encryption. Google apps are optional.

- [Download ROM, ARM64 TWRP, clean-install files and checksums](https://github.com/oddhap/lineageos21_gta3xlwifi/releases)
- [Installation](INSTALL_ARM64.md) and [GApps integration](docs/gapps-arm64-build.md)
- [Device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/lineage-21.0-arm64)

## 28 November 2026 update (2): e2fsck and Samsung FBE

Fixes [#6](https://github.com/oddhap/android_build_samsung_gta3xlwifi/issues/6):
after an unclean shutdown, the boot-time `e2fsck -y` moved every encrypted file
on /data to `lost+found` (`init_user0_failed`). The Samsung kernel sets
`EXT4_POLICY_FLAGS_PRIVATE_ALGO` (0x04) on files but not on directories, and
e2fsprogs 1.46 compared the full flags byte. The
[e2fsprogs patch](lineage-21/patches/external_e2fsprogs.patch) ignores the bit
for v1 policies with different contents/filenames modes, as the kernel does.
Build `gta3xlwifi.arm64.20261128.104453`; all 13 offline checks pass; physically
tested on the tablet with MindTheGapps and Magisk 31.1, including the unclean reboot.
[Investigation](reports/issue6-e2fsck-20261128/README.md),
[validation](reports/release-20261128-2/validation-summary.json).

## Previous update: 28 November 2026

TWRP `twrp-3.7.1_12-gta3xlwifi-arm64-20261128` is the 15 October LineageOS 21
TWRP with only `libminuitwrp.so` rebuilt for `ABGR_8888` (blue accent instead of
amber; the same library as in the LineageOS 24 TWRP). fstab (with /product),
crypto scripts, kernel and header are unchanged. The OTA recovery-header helper
recognizes the new image, so future builds keep its header in step with the ROM.
Build `gta3xlwifi.arm64.20261128.090043`; all 13 offline checks pass; not yet
physically tested on LineageOS 21.
[Validation](reports/release-20261128/validation-summary.json),
[TWRP rewrite](lineage-21/twrp/abgr-20261128/).

## Previous update: 27 November 2026

Ports three LineageOS 24 fixes and adds built-in updates:

- ART boot/system code is compiled for the CC collector the 4.4 kernel runs
  (`PRODUCT_ENABLE_UFFD_GC := false`).
- The power HAL retries failed boost writes after 1–60 s instead of disabling
  boost until reboot.
- SD card: `exfat` filesystem alias in the kernel's sdfat driver
  ([patch](lineage-21/kernel/exfat/)), adoptable storage and XTS/CTS volume
  encryption options ([#4](https://github.com/oddhap/android_build_samsung_gta3xlwifi/issues/4)).
- LineageOS Updater reads `gta3xlwifi.json` on the `ota` branch of the download
  repository; the OTA stops TWRP's crypto services and unmounts Vendor before
  the unchanged vendor-unmounted guard.

All 13 offline checks pass; not yet physically tested on LineageOS 21.
Build `gta3xlwifi.arm64.20261127.194723`, framework security patch **2026-10-01**.
[Validation](reports/release-20261127/validation-summary.json) and
[details](reports/release-20261127/README.md).

## Previous update: 24 November 2026

Backported classic Bluetooth headphone profiles and the compatible HIDL 2.0
audio path ([validation](reports/release-20261124/validation-summary.json)).

## Source and build

All 26 pinned port patches, the 1,430-project source manifest, device/build tools
and validation reports are included. See [source preparation](PUBLIC_BUILD.md)
and [build/signing workflow](BUILD_ARM64.md). Private signing keys are not distributed.
Only ARM64 ROM releases are maintained. SM-T515 is unsupported.

The ROM writes boot, system, product and vendor. See the installation guide for
clean installation and rollback. The framework patch date does not describe
the security level of the older Samsung kernel/vendor. Long-term stability,
microphone, codec/DRM and advanced storage features are not fully validated.
New code/configuration is Apache-2.0; upstream components retain their licenses.
