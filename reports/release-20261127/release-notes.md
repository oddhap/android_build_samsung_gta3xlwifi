LineageOS 21 / Android 14, **ARM64**, for **SM-T510 / gta3xlwifi**.

Fixes ported from the LineageOS 24 build:

- **Built-in updates:** Settings → System → Updater now finds new releases in this repository. Install this build once manually (TWRP or `adb sideload`); later builds can be installed from the Updater.
- **Installer:** it stops TWRP's recovery crypto services and unmounts Vendor by itself, so manual unmounting is normally no longer needed.
- **ART:** the framework and system apps are precompiled for the garbage collector this kernel actually runs. Earlier builds compiled them for a collector the 4.4 kernel cannot use, so Android rejected the precompiled code.
- **Touch/launch boost:** one failed CPU/GPU boost write no longer disables boosting until reboot; it retries after 1–60 seconds.
- **SD card:** exFAT cards mount, and SD cards can be adopted as internal storage ([#4](https://github.com/oddhap/android_build_samsung_gta3xlwifi/issues/4)).

All 13 offline release checks pass. These changes have not yet been physically tested on LineageOS 21.

Clean-install files are included below. Start with **INSTALL.md** and verify **SHA256SUMS**. Google apps are optional; the guide links the Android 14 ARM64 package.
