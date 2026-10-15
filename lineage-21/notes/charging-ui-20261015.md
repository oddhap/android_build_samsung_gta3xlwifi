# ARM64 off-mode charging display — October 15 follow-up

Report: https://github.com/oddhap/android_build_samsung_gta3xlwifi/issues/2.
This follow-up is scoped to the native ARM64 product with ARM32 app support.

The preceding ROM installed `/system/bin/charger` and Lineage charging animation
assets, including the percentage font, but defined no init service to run that
UI. The retained Samsung health service belongs to `hal charger` and provides
battery data; Samsung's `sec-charger` startup has no matching UI service in this
product. Android therefore had no configured platform charging display.

The device now explicitly includes the platform charger and copies a small
`init.gta3xlwifi.charger.rc` into system init. Its service is in `class charger`
only, with the existing `charger_exec` -> `charger` SELinux transition and
SYS_BOOT capability. It neither starts Android's main classes nor replaces the
Samsung battery HAL/charging-control driver. No permissive domains or new policy
bypasses are added. Normal Android startup leaves this UI service stopped.

All 280 LineageOS 21.0 branches were fetched again October 15; no revisions
changed since the October 14 snapshot. All 1,430 actual checkout HEADs match the
same immutable manifest. Android 14, framework SPL 2026-10-01 and WebView
155.0.8059.39 are retained. The DT2W kernel/native integration, DTBO and hybrid
vendor are retained. Existing signing material is reused without rotation.

Build identity: `gta3xlwifi.arm64.20261015.071117`.
Compiled device change: `1bed5efbc20d36fe6f673aac71e890392a4110ba`.
Full target-files/otatools compilation passes. `verify-charger-package.py` checks
the signed init service with host_init_verifier, native ARM64 executable, enabled
UI, fallback PNGs and actual Lineage animation/percentage assets.

All ten signed-package checks pass, including signatures, image bounds, ABI and
charger assets/startup. All 328 existing signing files are unchanged. Installed
over the October 14 beta without formatting data; CE storage, vold keys,
recovery payload, DTBO and vbmeta were preserved.

Physical powered-off charging was verified on SM-T510 after normal Android
shutdown with USB power connected. The animation shows the battery percentage.
At 100%, it displays for about seven seconds then blanks; a short Power press
shows it again, and holding Power starts Android. The owner confirmed no
repeated flickering while untouched for one minute. The previous charger-boot
log contains a single charger startup, without a fatal restart.

On return to Android, encrypted storage and SELinux Enforcing pass. Both Mali
ABIs render 120 frames with readback; all 104 baseline HALs, Wi-Fi/app HTTPS,
speaker, both cameras and accelerometer pass. Test apps and the storage marker
are removed and ADB is unrooted. DT2W uses the same kernel and byte-identical
native libraries as the physically verified October 14 build; its enabled
setting is retained. No new manual double-tap test is claimed for this build.
See [the hash-bound validation summary](../../reports/charging-20261015/validation-summary.json).

Publication replaces the existing October 14 beta release in place at the
owner's request. The original source is archived under the tag ending in
`-original`, and its signed ROM is retained locally. The compatible October 14
PIN-free TWRP download is unchanged. The ARM32 ROM has not been rebuilt.
