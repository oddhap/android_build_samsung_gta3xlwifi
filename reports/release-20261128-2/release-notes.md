LineageOS 21 / Android 14, **ARM64**, for **SM-T510 / gta3xlwifi**.

- **Fixes lost data after an unclean shutdown ([#6](https://github.com/oddhap/android_build_samsung_gta3xlwifi/issues/6)):** Android 14's boot-time `e2fsck` treated a Samsung-specific file encryption flag as a policy mismatch. After any unclean shutdown (Magisk's "additional setup" reboot, a crash, an empty battery) it moved every encrypted file to `lost+found` and Android stopped with `init_user0_failed`. `e2fsck` now ignores that flag the way the kernel does.
- Everything else is the 28 November build: TWRP colour fix, built-in updates, ART, touch-boost and SD card fixes.

Physically tested on the tablet: clean install + MindTheGapps, then Magisk 31.1 and its "additional setup" reboot. The forced boot check found nothing to repair, `lost+found` stayed empty, and Android booted. Data that was already moved to `lost+found` on an earlier build cannot be restored by this update.

On a 27 or 28 November build, this update is offered in the Updater. Older builds: install it once manually (see **INSTALL.md**). Start with **INSTALL.md** and verify **SHA256SUMS**. The TWRP and rollback files are unchanged from the 28 November release.
