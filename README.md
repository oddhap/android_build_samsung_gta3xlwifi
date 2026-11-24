# LineageOS 21 for SM-T510 — ARM64

Native **ARM64 Android 14** with **ARM32 app support**, for Samsung Galaxy Tab A
10.1 (2019), **SM-T510 / gta3xlwifi only**. Unofficial, signed with the existing
release keys, SELinux Enforcing and file-based encryption. Google apps are optional.

- [Download ROM, ARM64 TWRP, clean-install files and checksums](https://github.com/oddhap/lineageos21_gta3xlwifi/releases)
- [Installation](INSTALL_ARM64.md) and [GApps integration](docs/gapps-arm64-build.md)
- [Device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/lineage-21.0-arm64)

## 24 November 2026 update

Backports classic Bluetooth headphone profiles and the compatible HIDL 2.0 audio
path from the LineageOS 24 fix. Headset microphone and LE Audio remain outside
this fix. All 13 offline checks pass; physical pairing/playback confirmation on
LineageOS 21 is pending. No new framework source refresh is included.

Build `gta3xlwifi.arm64.20261124.190610`, framework security patch **2026-10-01**.
[Validation](reports/release-20261124/validation-summary.json).
New LineageOS 21 releases use the dedicated download repository linked above;
historical releases retain their existing URLs.

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
