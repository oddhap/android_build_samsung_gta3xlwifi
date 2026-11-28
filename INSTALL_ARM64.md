# LineageOS 21 ARM64 for SM-T510

Android 14, build `gta3xlwifi.arm64.20261128.090043`, framework security patch
2026-10-01. **SM-T510 / gta3xlwifi only**, not SM-T515. Native ARM64 Android
with ARM32 app support, SELinux Enforcing and file-based encryption.

The ROM writes **boot, system, product and vendor**. It retains partition sizes
and does not format userdata or write EFS. Google apps are optional and downloaded
separately. Only ARM64 releases will be maintained going forward.

## Downloads

- `lineage-21.0-20261128-UNOFFICIAL-gta3xlwifi-arm64.zip`: signed ROM.
- `twrp-3.7.1_12-gta3xlwifi-arm64-20261128.img`: native ARM64 TWRP 3.7.1_12,
  with working PIN, automatic PIN-free decryption and corrected colours.
- `twrp-3.7.1_12-gta3xlwifi-arm64-20261128-ap.tar`: Odin AP archive containing
  the same recovery and `vbmeta.img`.
- `vbmeta-disabled.img`: vbmeta for Heimdall; disables AVB, not storage encryption.
- `SHA256SUMS`: checksums for all assets.
- Stock CWA1 vendor image and guarded restore helper: for rollback only.

Keep a backup outside the tablet and verify SHA256SUMS before flashing.
Bootloader unlocking erases data and custom firmware can trip Knox. Keep the
bootloader unlocked with this ROM; leave **Re-Partition disabled**.

## Update an existing signed LineageOS 21 ARM64 installation

These update steps apply to LineageOS 21 ARM64. Moving from LineageOS 24 is a
downgrade and requires the clean-install procedure, including Format Data.

1. Boot the included ARM64 TWRP. The 28 November TWRP is the 15 October ARM64
   TWRP with corrected colours (blue accent instead of amber); only its display
   library changed. If you already use the 15 October ARM64 TWRP, you can keep it
   or update it the same way. Otherwise install its image using **TWRP → Install → Install Image →
   Recovery**, then **Reboot → Recovery**. This does not require Format Data.
   ARM32 TWRP must be replaced to install ARM64 GApps.
2. Enter your PIN on the tablet if prompted. Without a PIN, storage decrypts
   automatically. Confirm internal storage is accessible.
3. The installer stops TWRP's recovery crypto services and unmounts Vendor
   itself before it writes anything. If it still stops with a message that
   Vendor is mounted, stop only those recovery instances using
   Advanced → Terminal or `adb shell`:

   ```sh
   for service in keystore2 recovery-keymaster recovery-gatekeeper recovery-mobicore recovery-crypto-props; do
       setprop ctl.stop "$service"
   done
   ```

   Wait a few seconds, then unmount Vendor. The installer refuses to write
   images while Vendor is mounted; do not bypass that check.
4. Install the ROM ZIP, or use `adb sideload lineage-21.0-20261128-UNOFFICIAL-gta3xlwifi-arm64.zip`.
5. The ROM retains addon.d support for preserving an existing MindTheGapps
   installation. Preservation was physically verified with earlier LineageOS 21 ARM64 builds;
   this November 28 build has not been test-installed. Keep the same Android 14 ARM64
   package available in case recovery reports a restore failure. See the Google apps section before boot.
   **Do not Format Data for a routine update.**

## Built-in updates

From this build on, **Settings → System → Updater** checks this repository for
new LineageOS 21 releases. Installations older than this build do not know the
update address: install this build once with the steps above. Later releases
can then be downloaded and installed from the Updater; the tablet reboots into
the ARM64 TWRP, which installs the package and preserves MindTheGapps through
addon.d. Packages are only accepted if signed with the same release key.
The unattended install path was physically verified with LineageOS 24 and its
TWRP (same TWRP 3.7.1_12 base); it has not yet been physically tested with
LineageOS 21.

## SD card as internal storage

This build supports exFAT SD cards and adopting an SD card as internal storage
(**Settings → Storage → SD card → Format as internal**). Adopting erases the card.
Not yet physically tested on LineageOS 21.

## First installation from stock or another ROM

1. Start from **T510XXU5CWA1 / T510OXM5CVG2** firmware. Unlock the bootloader,
   boot stock once, connect to the Internet and confirm OEM unlocking remains enabled.
2. In Download Mode, flash the supplied AP archive using Odin's **AP** field.
   Disable **Auto Reboot** and **Re-Partition**.
3. Boot directly into recovery: keep USB connected, hold Power + Volume Down
   until the screen turns black, switch to Power + Volume Up, release Power at
   the logo and hold Volume Up until TWRP appears.
4. Use **Wipe → Format Data → type yes** for this clean installation. This erases
   internal storage. Reboot to Recovery. Keep the ROM on microSD/USB OTG or use
   sideload so your only copy is not erased.
5. Follow the update steps to install the ROM with Vendor unmounted.
   The ROM includes its hybrid vendor; do not flash the complete donor firmware
   or resize partitions.
6. If wanted, install GApps **before the first Android boot**, then reboot System.

Heimdall alternative for the recovery installation:

```sh
heimdall flash --RECOVERY twrp-3.7.1_12-gta3xlwifi-arm64-20261128.img --VBMETA vbmeta-disabled.img --no-reboot
```

## Optional Google apps

Use **Android 14 / ARM64 MindTheGapps** with the supplied **ARM64 TWRP**.
The package tested on this tablet is
[MindTheGapps-14.0.0-arm64-20250203_200051.zip](https://github.com/MindTheGapps/14.0.0-arm64/releases/tag/MindTheGapps-14.0.0-arm64-20250203_200051),
SHA-256 `6e1c3616862ce5b33e2b96074f86ae846eb1351a26a980e1ed140f8a7e7a4fd6`.

Install the **original ZIP unchanged**, immediately after the ROM and before
first boot. Its built-in minimum configuration is selected because the product
partition is small. No architecture spoofing, partition resizing or patched
Google ZIP is needed. Google apps are not included in the ROM download.

Adding GApps to an already configured installation has not been validated.
For a clean GApps installation, back up your files and follow the clean-install
process. Do not install ARM GApps on this ARM64 ROM.

## Older ROMs and rollback

The ROM uses a hybrid vendor based on stock SM-T510 CWA1 with selected ARM64
SM-A305GT graphics libraries. The old ARM32 ZIP preserves vendor, so flashing
it alone after this ROM leaves an incompatible vendor installed.

For rollback, use the supplied stock vendor image and guarded helper **before**
installing the old ARM32 ROM. See the previous release's full rollback procedure:
[October 15 charging release](https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases/tag/lineage-21.0-arm64-beta-20261014).
Use a recovery with matching OS/SPL metadata. Downgrading security patch levels
with retained userdata has not been validated; keep a matching backup.

## Test scope and remaining limits

The ROM retains working double tap to wake and powered-off charging display
support. Enable **Settings → Display → Tap to wake**. On a full battery, the
charging display normally blanks after about seven seconds; short Power shows
it again and long Power starts Android.

Google login and app installation, ARM64 Google services, both Mali graphics
ABIs, Wi-Fi/app internet, speaker, both cameras, accelerometer and PIN/PIN-free
recovery have been tested. These results apply to earlier LineageOS 21 ARM64 builds. This build passes
13 offline checks. Bluetooth pairing, playback and reconnect, the ART, boost,
SD card and Updater changes in this build require physical confirmation on
LineageOS 21.

Long-term stability, Bluetooth pairing/audio, microphone, video/DRM codecs,
advanced graphics/storage features, Play Integrity and encrypted backup/restore
are not fully validated. Legacy
Samsung vendor/kernel components remain older than the framework patch date.
