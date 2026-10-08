# SM-T510 ARM64 beta — installation and rollback

LineageOS 21 / Android 14, build `gta3xlwifi.arm64.20261007.170546`.
Only **SM-T510 / gta3xlwifi** is supported. Not SM-T515.
Published 2026-10-08; ROM and recovery built/tested 2026-10-07.

This beta has native ARM64 userspace and supports ARM32 apps. It retains the
existing partition layout and uses a minimal hybrid vendor based on SM-T510
CWA1 plus selected ARM64 SM-A305GT graphics libraries. **The beta ZIP writes
boot, system, product AND vendor.** It does not format userdata or write EFS.
No GApps are included. Backup your files externally before changing firmware.

## Files

- `lineage-21.0-20261007-UNOFFICIAL-gta3xlwifi-arm64-beta.zip` — the exact signed, physically tested ROM, renamed for the beta release.
- `twrp-3.7.1_12-gta3xlwifi-pinfree-20261007.img` — updated TWRP; encrypted data works with PIN and without PIN.
- `twrp-3.7.1_12-gta3xlwifi-pinfree-20261007-ap.tar` — Odin AP archive containing recovery.img and vbmeta.img.
- `vbmeta-disabled.img` — separate vbmeta for Heimdall.
- `vendor-stock-T510XXU5CWA1.raw.img` — original stock vendor from the downloaded
  firmware, for returning to the ARM32 ROM. Contains no device backup or userdata.
- `RESTORE_STOCK_VENDOR.sh` — guarded TWRP-only stock-vendor restore helper.
- `SHA256SUMS` — verify all downloads before flashing.

Bootloader unlocking erases data and custom firmware can permanently trip Knox.
Do not relock the bootloader with custom firmware installed. Leave Re-Partition
disabled. The supplied vbmeta disables AVB verification, not storage encryption.

## Upgrade from this project's signed ARM32 LineageOS 21 release

The in-place migration from the 2026-10-05 ARM32 build was physically tested:
existing apps, release-key identity, userdata and FBE were retained.

1. Download the beta ZIP, updated TWRP and recovery installation files. Verify
   the checksums. Keep the ZIP on microSD/USB OTG or ready for ADB sideload.
2. In existing TWRP, install `twrp-3.7.1_12-gta3xlwifi-pinfree-20261007.img` with **Install → Install Image → Recovery**,
   then reboot to **Recovery**. Alternatively flash the AP archive in Download Mode
   as below. Do not format data just to update recovery.
3. If you have a PIN, enter it on the tablet. With no PIN, the updated TWRP
   automatically decrypts user 0 storage. Confirm your storage is accessible.
4. Uncheck Vendor in Mount. If recovery's crypto services hold vendor mounted,
   use Advanced → Terminal (or `adb shell`) to stop their recovery instances:

   ```sh
   for service in keystore2 recovery-keymaster recovery-gatekeeper recovery-mobicore recovery-crypto-props; do
       setprop ctl.stop "$service"
   done
   ```

   Wait a few seconds, then unmount Vendor. Leave it unmounted. This is needed
   because this beta installs its own vendor image. The installer refuses to
   write images while vendor is mounted; do not bypass that guard.
5. Install `lineage-21.0-20261007-UNOFFICIAL-gta3xlwifi-arm64-beta.zip`, then reboot to System. **Do not Format Data for this upgrade.**
   First boot takes longer than a normal reboot.

ADB sideload alternative:

```sh
adb sideload lineage-21.0-20261007-UNOFFICIAL-gta3xlwifi-arm64-beta.zip
```

## First installation from stock or another ROM

1. Start with **T510XXU5CWA1 / T510OXM5CVG2** stock firmware. Unlock the bootloader,
   boot stock once, connect to the Internet and confirm OEM unlocking remains enabled.
2. In Download Mode, use `twrp-3.7.1_12-gta3xlwifi-pinfree-20261007-ap.tar` in Odin's **AP** field.
   Disable **Auto Reboot** and **Re-Partition**.
3. Boot directly into recovery before allowing stock Android to start. Keep USB
   connected: Power + Volume Down until the screen turns black, then switch to
   Power + Volume Up; release Power at the logo and hold Volume Up for TWRP.
4. From stock/another ROM, use **Wipe → Format Data → type yes**. This erases
   internal storage. Reboot to Recovery and install from microSD/USB OTG or
   sideload; keep your only ROM copy off internal storage.
5. Follow steps 3–5 of the upgrade instructions. The beta installs hybrid vendor
   itself; do not flash the complete donor firmware or change partition sizes.

Heimdall alternative for step 2:

```sh
heimdall flash --RECOVERY twrp-3.7.1_12-gta3xlwifi-pinfree-20261007.img --VBMETA vbmeta-disabled.img --no-reboot
```

## Return to the previous ARM32 LineageOS 21 release

**The old ARM32 ZIP preserves vendor. Flashing it alone after this ARM64 beta
leaves the wrong vendor installed. Restore stock vendor FIRST.**

1. Download `vendor-stock-T510XXU5CWA1.raw.img` and `RESTORE_STOCK_VENDOR.sh`
   from this beta release, and `lineage-21.0-20261005-UNOFFICIAL-gta3xlwifi.zip`
   from the previous GitHub release.
   Verify their checksums and keep an external backup.
2. Boot the new PIN-free TWRP. Decrypt data if needed. Keep the new recovery;
   it already has the Android 14 / September 2026 compatibility header.
3. Restore stock vendor with the guarded helper, which stops recovery crypto
   services, requires vendor to be unmounted, checks image/partition identity,
   writes only vendor and verifies its full readback:

   ```sh
   adb push vendor-stock-T510XXU5CWA1.raw.img /tmp/vendor-stock-T510XXU5CWA1.raw.img
   adb push RESTORE_STOCK_VENDOR.sh /tmp/RESTORE_STOCK_VENDOR.sh
   adb shell sh /tmp/RESTORE_STOCK_VENDOR.sh /tmp/vendor-stock-T510XXU5CWA1.raw.img
   adb shell rm /tmp/vendor-stock-T510XXU5CWA1.raw.img
   ```

   Removing that staged image frees recovery RAM for the old ZIP. Stop if the
   helper reports a failure. Do not reboot Android with mixed ROM/vendor inputs.
4. Install the original signed ARM32 ZIP, then reboot to System. The tested
   rollback preserved userdata; no Format Data was used.

Previous release: https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases/tag/lineage-21.0-20261005

## Recovery/header scope

This beta ZIP is the exact tested 2026-10-07 package. Its earlier header helper
does not recognize the new recovery payload and leaves it unchanged; both
already use Android 14 / 2026-09-01 compatibility metadata. Source for future
builds recognizes both recovery payloads. Other Android major versions or
security-patch inputs are outside this test scope.

## Beta test scope

Verified: native ARM64 processes; ARM32/ARM64 GLES graphics on Mali-G71; Wi-Fi,
DNS/TLS/HTTPS; speaker output; front/back Camera2 frames; accelerometer;
Bluetooth controller activation; all 104 responsive baseline HAL interfaces;
encrypted storage; PIN and PIN-free TWRP; ROM boot and rollback.

Not fully tested: long-term stability, Bluetooth pairing/audio, microphone,
video/DRM codecs, microSD/OTG on this ARM64 build, deep suspend, Vulkan, OpenCL,
RenderScript, GApps/microG/Play Integrity, adoptable storage and encrypted
backup/restore. Built-in OTA downloads are not configured.
Framework SPL: 2026-09-01; the legacy Samsung vendor/kernel remain older.
