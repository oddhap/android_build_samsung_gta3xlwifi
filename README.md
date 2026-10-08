# LineageOS 21 for SM-T510 — ARM64 beta

Native **ARM64 Android 14** with **ARM32 app support**, for Galaxy Tab A 10.1
(2019) **SM-T510 / gta3xlwifi only**. Unofficial **beta**, no GApps, signed with
the existing project release keys, SELinux Enforcing and file-based encryption.
The previous ARM32 source/release remains on `lineage-21.0`.

- [Beta ROM, updated PIN-free TWRP and install/rollback guide](https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases/tag/lineage-21.0-arm64-beta-20261007)
- [ARM64 device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/lineage-21.0-arm64)
- [ROM kernel](https://github.com/oddhap/android_kernel_samsung_gta3xlwifi/tree/lineage-21.0)
- [Stock vendor inputs](https://github.com/oddhap/android_vendor_samsung_gta3xlwifi/tree/lineage-21.0)
- [Updated TWRP code](https://github.com/oddhap/android_device_samsung_gta3xlwifi_twrp/tree/twrp-12.1)

The beta ZIP installs a minimal hybrid vendor containing selected ARM64 graphics
libraries from SM-A305GT A305GTVJU8CWE1 ZTO while preserving Samsung's existing
ARM32 HAL/TEE stack. **It writes vendor; returning to the ARM32 ROM requires
restoring stock CWA1 vendor first.** See the release's INSTALL.md.

## Sources and build

This branch contains all 13 pinned platform patches, ARM64 device/build/staging
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

This remains a beta: long-term stability, Bluetooth pairing/audio, microphone,
video/DRM codecs and advanced graphics/storage features are not fully tested.
New tools/configuration are Apache-2.0 unless otherwise noted. Upstream
patches, kernel and proprietary firmware retain their original licenses.
