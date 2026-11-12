# LineageOS 21 for SM-T510 — ARM64

Native **ARM64 Android 14** with **ARM32 app support**, for Samsung Galaxy Tab A
10.1 (2019), **SM-T510 / gta3xlwifi only**. Unofficial, signed with the existing
release keys, SELinux Enforcing and file-based encryption. Google apps are optional.

- [Download ROM, ARM64 TWRP, checksums and installation guide](https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases/tag/lineage-21.0-arm64-20261112)
- [Installation](INSTALL_ARM64.md) and [GApps integration](docs/gapps-arm64-build.md)
- [Device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/lineage-21.0-arm64)

## 12 November 2026 update

- Updated to the latest available LineageOS 21 sources.
- Fixed the lowest brightness setting switching off the backlight.

Build `gta3xlwifi.arm64.20261112.200307`, framework security patch **2026-10-01**.
All 12 offline release checks pass; physical testing of this build is pending.
[Validation](reports/release-20261112/validation-summary.json).

## Source and build

All 25 pinned port patches, the 1,430-project source manifest, device/build tools
and validation reports are included. See [source preparation](PUBLIC_BUILD.md)
and [build/signing workflow](BUILD_ARM64.md). Private signing keys are not distributed.
Only ARM64 ROM releases are maintained. SM-T515 is unsupported.

The ROM writes boot, system, product and vendor. Returning to ARM32 requires
restoring stock CWA1 vendor first; see the installation guide. The framework
patch date does not describe the security level of the older Samsung kernel/vendor.
Long-term stability and all Bluetooth, microphone, codec/DRM and advanced storage
features are not fully validated. Built-in OTA downloads are not configured.
New code/configuration is Apache-2.0; upstream components retain their licenses.
