# ARM64 GApps integration for SM-T510

The original MindTheGapps Android 14 ARM64 installer reads `ro.bionic.arch`
from recovery. The ARM64 ROM previously used ARM32 TWRP, so installation stopped
at the architecture check. Product capacity was a separate obstacle: the fixed
327,155,712-byte product partition did not have room for the package's minimum
payload. Both constraints must be addressed.

The new TWRP uses native AArch64 recovery, ADB, keystore2 and graphics libraries.
Samsung's vendor crypto executables retain their existing ARM32 ABI. Their
source-built compatibility libraries are staged by `prepare-twrp-compat32.py`,
with dependency and SHA-256 checks; each vendor service has an explicit ARM32
library path. The recovery kernel, DTBO, FBE fixes and USB setup are retained.
The compressed recovery ramdisk remains below the bootloader's 16 MiB limit.

Selected ROM apps move from product to system, which has sufficient capacity.
Their JNI libraries, privileged permission allowlists and companion XML modules
move with them. The Android 14 Make relocation variable does not change Soong
install paths, so the Soong module changes are included in the pinned platform
patches. `configure-gapps-product-layout.py` documents the exact files and
expected property counts. No app or partition is removed or resized.

`verify-gapps-headroom.py` reads the product image directly from target-files,
checks actual ext4 free space against the original installer's minimum payload
plus its 10 MiB buffer, verifies app/JNI/allowlist destinations, and compares APK
names with the previous release. Run it before signing, then against the signed
target-files and signature report. The corrected signed candidate has
267,526,144 bytes available against a 235,712,512-byte requirement; all 150
previous APK names are retained. Both unsigned and signed checks pass.

The supplied Google ZIP is unmodified:
`MindTheGapps-14.0.0-arm64-20250203_200051.zip`, SHA-256
`6e1c3616862ce5b33e2b96074f86ae846eb1351a26a980e1ed140f8a7e7a4fd6`.
The installer can select its built-in minimum configuration on this small
product partition. Google apps are not bundled in the ROM source build.

On the physical SM-T510, both the ROM and unmodified Google ZIP install with
updater exit code zero. All 29 mandatory Google payload files match the original
ZIP byte for byte; about 40 MiB remains on product. The installer selects its
own minimum configuration. Setup and Wi-Fi complete normally. The owner signed
in privately and confirmed that a free app downloaded, installed and launched.
Google Play services 26.39.33 and Play Store 53.5.48-34 run as native AArch64
processes; after their initial automatic updates, both remained stable during
a 63-second check with no Google process crashes. SELinux remains enforcing
and user storage remains file encrypted.

Both ARM64 and ARM32 Mali rendering tests pass, including window drawing and
pixel readback. Hardware smoke checks pass for the 98 concrete baseline HALs,
Wi-Fi/internet, accelerometer, audio, and both cameras. These checks do not
establish long-term reliability or Bluetooth pairing behavior.

The native recovery GUI, trusted vendor Keymaster access, and execution of the
Google ZIP's original ARM64 toybox pass. Recovery and all four crypto services
remained alive from boot for over 39 minutes before ROM installation.
Post-provisioning PIN and PIN-free FBE tests both pass: credential-encrypted
media read/write, CE SQLite header access, preservation of all 13 encryption-key
files, over 60 seconds of recovery stability per round, and normal Android
return with the recovery write preserved. The owner enters credentials only
on the tablet; no PIN is collected by the test tools.

A Wi-Fi setup callback defect was found after provisioning: a queued callback
could access the fragment's activity after detachment. An `isAdded()` guard
was first compiled into a separately signed Settings update and tested through
six Wi-Fi open/scan/close cycles, including setup Next-button mode. That initial
workaround is not present in initial GApps ROM SHA-256
`1c44971bcbe315fb6912c055cce3818fdc5e3a0e1b9b830fef11b874d1aa4567`.

Publication build `gta3xlwifi.arm64.20261015.191854`, ROM SHA-256
`f4505aef35f10de09c629dfb6cdfffd219e5a01bf7b67c5b5bf7a6a0ad093781`,
bakes the guard into the ROM. All three Settings DEX files match the physically
tested app update byte for byte. A separate app update is no longer required,
and the fix is retained across factory reset. This build passes all ten signed
offline checks, native VINTF/vendor policy checks, unchanged-key checks, and
signed GApps headroom checks. All 280 official LineageOS 21 projects were fetched
again before building; no additional upstream revisions were found.

The signed publication OTA was installed over the configured GApps build without
formatting. All 29 mandatory original Google files survived addon.d and match
the ZIP byte for byte. Android booted with readable CE storage and the persistent
encryption keys preserved. Vendor's file data and fixed metadata match the
reviewed image across the entire partition. Only 18 bytes of ext4 mount counters,
timestamps, initialized-inode flags and corresponding checksums differ after
mounting; read-only e2fsck passes. The new readback checker rejects changes
outside those precisely allowed fields, including an injected data-byte change.
