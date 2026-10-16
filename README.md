# LineageOS 21 for SM-T510 — ARM64

Native **ARM64 Android 14** with **ARM32 app support**, for Galaxy Tab A 10.1
(2019) **SM-T510 / gta3xlwifi only**. Unofficial, signed with the existing project
release keys, SELinux Enforcing and file-based encryption. Google apps are
optional and are not bundled. Only ARM64 releases are maintained going forward.
The historical ARM32 source/release remains on `lineage-21.0`.

- [ROM, native ARM64 TWRP, checksums and installation guide](https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases/tag/lineage-21.0-arm64-20261015)
- [Installation](INSTALL_ARM64.md) and [GApps integration details](docs/gapps-arm64-build.md)
- [ARM64 device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/lineage-21.0-arm64)
- [ROM kernel](https://github.com/oddhap/android_kernel_samsung_gta3xlwifi/tree/lineage-21.0)
- [Stock vendor inputs](https://github.com/oddhap/android_vendor_samsung_gta3xlwifi/tree/lineage-21.0)
- [Native ARM64 TWRP source](https://github.com/oddhap/android_device_samsung_gta3xlwifi_twrp/tree/twrp-12.1-arm64)

The ZIP installs a minimal hybrid vendor containing selected ARM64 graphics
libraries from SM-A305GT A305GTVJU8CWE1 ZTO while preserving Samsung's existing
ARM32 HAL/TEE stack. **It writes vendor; returning to an ARM32 ROM requires
restoring stock CWA1 vendor first.** See INSTALL_ARM64.md.

## ARM64 GApps and recovery update (October 15 build)

Native ARM64 TWRP and the ROM's product-layout changes allow the original
MindTheGapps Android 14 ARM64 package to install unchanged. PIN and automatic
PIN-free CE decryption, recovery read/write and Android return pass physical
tests. The owner confirmed Google login and a working Play Store app download.
The ROM also includes a guard against a delayed Wi-Fi setup callback accessing
a detached Settings screen. Working double tap to wake and off-mode charging
support are retained. See [current build status](BUILD_STATUS.md) and
[hardware results](reports/gapps-arm64-20261015/validation-summary.json).

## October 15 charging display update

Build `gta3xlwifi.arm64.20261015.071117` starts the native charger UI while
Android is powered off. Battery percentage, normal automatic blanking, short
Power to show it again and long Power to boot Android were physically verified.
The existing beta release above is updated in place. LineageOS 21 sources were
fetched again October 15, with no revision changes since October 14. The DT2W
kernel/native code and compatible PIN-free TWRP are retained.
See [charging fix details](lineage-21/notes/charging-ui-20261015.md) and
[validation results](reports/charging-20261015/validation-summary.json).

## October 14 source update

The October 14 build adds working double tap to wake and pins the latest
LineageOS 21.0 revisions fetched on October 14, with framework SPL 2026-10-01.
It was installed over the October 7 ARM64 beta with data preserved. Physical
wake, both Mali graphics ABIs, basic hardware, and PIN-free recovery/Android
return were verified. Enable **Settings → Display → Tap to wake**.
See [release details](lineage-21/notes/double-tap-wake-20261014.md) and the
[hash-bound validation summary](reports/dt2w-20261014/validation-summary.json).
The October 7 release remains available unchanged.

## Sources and build

This branch contains all 25 pinned platform patches, ARM64 device/build/staging
tools, donor extraction and image preparation, complete recovery patches,
multilib graphics/hardware test sources and public validation reports.

See [PUBLIC_BUILD.md](PUBLIC_BUILD.md) for source/input preparation and
[BUILD_ARM64.md](BUILD_ARM64.md) for the tested build/signing workflow. The
private signing keys used for published binaries are not distributed.
[BUILD_STATUS.md](BUILD_STATUS.md) records the exact tested build and limits.

Public reports: [ROM](reports/arm64/arm64-validation-summary.json) and
[PIN-free TWRP](reports/twrp-pinfree/validation-summary.json). Earlier offline
reports describe the phase when they were generated; the final summaries bind
the subsequent physical tests. Raw logs, credentials and userdata/EFS backups
are excluded.

Long-term stability, Bluetooth pairing/audio, microphone,
video/DRM codecs and advanced graphics/storage features are not fully tested.
New tools/configuration are Apache-2.0 unless otherwise noted. Upstream
patches, kernel and proprietary firmware retain their original licenses.
