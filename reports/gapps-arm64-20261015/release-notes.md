Native **ARM64 LineageOS 21 / Android 14** for **SM-T510 / gta3xlwifi**, with ARM32 app support. Build `gta3xlwifi.arm64.20261015.191854`, signed with the existing project keys. Built October 15; published October 16, 2026. Only ARM64 releases will be maintained going forward.

This release adds **native ARM64 TWRP 3.7.1_12** and enough product space for the original **Android 14 ARM64 MindTheGapps** package to install unchanged. Google apps remain optional and are not bundled. Selected ROM apps, JNI libraries and permission files move to system; all 150 previous APK names and the existing partition sizes are retained.

Also included: a fix for a delayed Wi-Fi setup callback that could crash Settings after leaving the Wi-Fi screen. Working double tap to wake and the powered-off charging display fix are retained. SELinux remains Enforcing and file-based encryption is preserved.

LineageOS 21 sources were refreshed October 15 and checked again before this build: no additional revisions since the tested GApps build. Framework patch date is **2026-10-01**; Samsung vendor/kernel components remain older.

**Validation:** The final signed ROM passes all ten offline/package checks, native VINTF/vendor-policy checks and GApps space checks. A non-wiping update to this exact build preserves CE storage, encryption keys and all 29 original GApps payload files through addon.d. Google Play services and Play Store run as native ARM64 processes and remain stable during the post-update check, with no Google crashes. Both Mali graphics ABIs, all 98 concrete baseline HALs, Wi-Fi/app HTTPS, speaker output, both cameras and accelerometer pass. The owner confirmed Google login and a working Play Store app download on the initial GApps build. The included unchanged ARM64 TWRP passed real PIN and automatic PIN-free CE read/write and Android-return tests on that build. The Wi-Fi guard in the final ROM matches all three DEX files from the physically tested Settings update. Test apps are removed and ADB root is off.

Use the supplied **ARM64 recovery**, not the older ARM32 TWRP, for ARM64 GApps. Read **INSTALL.md** and verify **SHA256SUMS**. For a clean GApps installation, flash the ROM and then the [original tested MindTheGapps package](https://github.com/MindTheGapps/14.0.0-arm64/releases/tag/MindTheGapps-14.0.0-arm64-20250203_200051) before the first Android boot. Routine signed ARM64 updates do not require Format Data. The ROM writes boot, system, product **and vendor**; the installation guide explains Vendor unmounting and rollback.

Long-term stability, Bluetooth pairing/audio, microphone, video/DRM codecs, advanced graphics/storage features, Play Integrity and encrypted backup/restore are not fully validated. Built-in OTA downloads are not configured.

Downloads: ROM ZIP, ARM64 recovery image, Odin AP archive, vbmeta, installation guide, checksums and stock-vendor rollback files.

ROM SHA-256: `f4505aef35f10de09c629dfb6cdfffd219e5a01bf7b67c5b5bf7a6a0ad093781`

Sources: [pinned integration snapshot](https://github.com/oddhap/android_build_samsung_gta3xlwifi/commit/80b907e198508ea32d17e694d11403a2ab05f5ca), [device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/commit/9103cae139f954cccb5d9b01808787571db3189e), [ARM64 TWRP](https://github.com/oddhap/android_device_samsung_gta3xlwifi_twrp/commit/236a99beb2aa0a947b53f320845d1d132debff49), [kernel](https://github.com/oddhap/android_kernel_samsung_gta3xlwifi/commit/669b9584e678ce5865ed38e04c24639082d78de1), [vendor inputs](https://github.com/oddhap/android_vendor_samsung_gta3xlwifi/commit/29e8615b2f4af1da936bd791af45cd9632c286f7).
