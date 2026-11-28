# LineageOS 21 for SM-T510 — ARM64

Native **ARM64 Android 14** with **ARM32 app support**, for Samsung Galaxy Tab A
10.1 (2019), **SM-T510 / gta3xlwifi only**. Unofficial, signed with the existing
release keys, SELinux Enforcing and file-based encryption. Google apps are optional.

- [Download ROM, ARM64 TWRP, clean-install files and checksums](https://github.com/oddhap/lineageos21_gta3xlwifi/releases)
- [Installation](INSTALL_ARM64.md) and [GApps integration](docs/gapps-arm64-build.md)
- [Device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/lineage-21.0-arm64)

## 27 November 2026 update

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

All 25 pinned port patches, the 1,430-project source manifest, device/build tools
and validation reports are included. See [source preparation](PUBLIC_BUILD.md)
and [build/signing workflow](BUILD_ARM64.md). Private signing keys are not distributed.
Only ARM64 ROM releases are maintained. SM-T515 is unsupported.

The ROM writes boot, system, product and vendor. See the installation guide for
clean installation and rollback. The framework patch date does not describe
the security level of the older Samsung kernel/vendor. Long-term stability,
microphone, codec/DRM and advanced storage features are not fully validated.
New code/configuration is Apache-2.0; upstream components retain their licenses.
