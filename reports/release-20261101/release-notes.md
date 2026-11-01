Native **LineageOS 21 / Android 14**, ARM64 with ARM32 app support, for **Samsung Galaxy Tab A 10.1 (2019), SM-T510 / gta3xlwifi only**.

### Changes

- Updated to the latest available LineageOS 21 sources fetched on 1 November 2026. Android framework security patch: **2026-10-01**.
- Updated WebView to **156.0.8078.47** and the trust-store sources.
- Fixed USB file transfer (MTP), including normal selection of file-transfer mode with or without USB debugging.
- Retains double tap to wake, the powered-off charging display, file-based encryption and ARM64 GApps support.

Google apps are optional and are not bundled. Use an unmodified **Android 14 ARM64** GApps package if required.

### Downloads and installation

- ROM: `lineage-21.0-20261101-UNOFFICIAL-gta3xlwifi-arm64.zip`
- ARM64 TWRP: the unchanged, previously tested 15 October recovery is included for convenience.
- Follow **INSTALL.md** and check **SHA256SUMS** before installation.

The ROM writes boot, system, product and the hybrid vendor partition. Existing ARM64 users can update without formatting data. Returning to an ARM32 ROM requires restoring the included SM-T510 stock vendor first.

### Validation

The signed package passes all eleven offline release checks, actual-vendor VINTF/policy linking and ARM64 GApps capacity checks. The exact included MTP configuration passed storage enumeration, 16 MiB uploads/downloads with matching SHA-256, ADB mode switches and reboot testing on the 15 October ROM. **This complete new ROM image has not been test-installed on the tablet.** See the [validation report](https://github.com/oddhap/android_build_samsung_gta3xlwifi/blob/lineage-21.0-arm64/reports/release-20261101/validation-summary.json).

The framework patch date does not describe the security level of the older Samsung kernel/vendor stack. Long-term stability and all Bluetooth, microphone, codec/DRM and advanced storage features are not fully validated. Xubuntu/Thunar itself has not been tested directly.

Build: `gta3xlwifi.arm64.20261101.092053`.
Sources: [build integration](https://github.com/oddhap/android_build_samsung_gta3xlwifi/tree/lineage-21.0-arm64), [device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/lineage-21.0-arm64).
