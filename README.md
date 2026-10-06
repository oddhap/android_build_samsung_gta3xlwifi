# LineageOS for Samsung Galaxy Tab A 10.1 (2019)

Unofficial native LineageOS 21 / Android 14 for **SM-T510 / gta3xlwifi**.
ARM32 userspace, ARM64 Linux 4.4.302 kernel, file-based encryption and no GApps.
The ROM uses Samsung CWA1 vendor firmware and the original partition layout.

This repository contains the platform patches, source manifests and build tools.
The `lineage-21.0` branch contains the Android 14 port; the legacy Android 12L
integration is retained on `main`.

- [ROM downloads](https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases)
- [Device tree](https://github.com/oddhap/android_device_samsung_gta3xlwifi/tree/lineage-21.0)
- [Kernel](https://github.com/oddhap/android_kernel_samsung_gta3xlwifi/tree/lineage-21.0)
- [Vendor](https://github.com/oddhap/android_vendor_samsung_gta3xlwifi/tree/lineage-21.0)
- [TWRP](https://github.com/oddhap/android_device_samsung_gta3xlwifi_twrp)

Platform changes provide compatibility with the legacy kernel/vendor, CPU/GPU
boosting and TWRP encryption-header synchronization during ROM ZIP updates.
32-bit apps are supported; ARM64-only apps are not. Built-in OTA downloads are
not configured.

New tools/configuration are Apache-2.0 unless otherwise noted. Platform patches,
kernel sources and proprietary blobs retain their original licenses.
