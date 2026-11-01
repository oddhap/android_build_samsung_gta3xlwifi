> Current development target: [LineageOS 24.0 / Android 17](lineage-24.0/README.md).
> The LineageOS 21 release below remains the existing supported rollback reference.

# LineageOS 21 for SM-T510 — ARM64

Native **ARM64 Android 14** with **ARM32 app support**, for Galaxy Tab A 10.1
(2019) **SM-T510 / gta3xlwifi only**. Unofficial, signed with the existing project
release keys, configured for SELinux Enforcing and file-based encryption.
Google apps are optional and are not bundled. Only ARM64 ROM releases are maintained.

- [ROM, ARM64 TWRP, checksums and installation guide](https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases/tag/lineage-21.0-arm64-20261101)
- [Installation](INSTALL_ARM64.md) and [GApps integration](docs/gapps-arm64-build.md)
- [ARM64 device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/lineage-21.0-arm64)
- [Kernel](https://github.com/oddhap/android_kernel_samsung_gta3xlwifi/tree/lineage-21.0)
- [Stock vendor inputs](https://github.com/oddhap/android_vendor_samsung_gta3xlwifi/tree/lineage-21.0)

## 1 November 2026 update

Build `gta3xlwifi.arm64.20261101.092053` includes the latest available LineageOS 21
sources fetched on 1 November: 12 updated projects among
281 fetched Lineage refs, including WebView 156.0.8078.47 and the
trust-store sources. Framework security patch remains **2026-10-01**.
USB file transfer now uses a single FunctionFS MTP/PTP configuration, resolving
the conflicting Samsung and generic USB setup. Double tap to wake, the powered-off
charging display and ARM64 GApps capacity are retained.

The signed package passes all eleven offline release checks and the GApps
capacity check. The exact MTP configuration was physically tested on the
15 October ROM; the complete new ROM has not been test-installed.
See [validation](reports/release-20261101/validation-summary.json) and
[MTP details](lineage-21/notes/mtp-20261101.md).

The ZIP writes boot, system, product and a minimal hybrid vendor. Returning to
an ARM32 ROM requires restoring stock CWA1 vendor first. Use the unchanged,
previously tested native ARM64 TWRP from 15 October; see INSTALL_ARM64.md.

## Source and build

The repository contains all 25 pinned platform patches, the complete 1,430-project
manifest, device/build/staging tools, donor extraction, recovery patches and
validation reports. See [source preparation](PUBLIC_BUILD.md) and
[build/signing workflow](BUILD_ARM64.md). Private signing keys are not distributed.
Earlier releases, source tags and reports remain available.

Long-term stability, Bluetooth pairing/audio, microphone, video/DRM codecs and
advanced graphics/storage features are not fully tested. Xubuntu/Thunar itself
has not been directly tested. New tools/configuration are Apache-2.0; upstream
code, kernel and proprietary firmware retain their original licenses.
