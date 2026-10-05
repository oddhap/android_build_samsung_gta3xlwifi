# Automatic SM-T510 TWRP header synchronization

LineageOS 21 non-A/B signed OTA packages now carry a static ARM32 helper and
device-specific full/incremental install hooks. The target OS word comes from
the package's actual boot image and must match its Android 14 / security-patch
properties. Preflight runs before partition installation; synchronization runs
after the new boot image is written.

The helper opens only the original 47,185,920-byte RECOVERY partition, resolves
the expected Samsung by-name path to mmcblk0p16 and recognizes the physically
tested TWRP 3.7.1_12 using a SHA-256 over its complete marked image with only
the four OS-word bytes excluded. Kernel, ramdisk, DTBO, other header fields and
trailer must match. This permits repeated metadata synchronization without
rebuilding or replacing TWRP.

Unsupported recovery images are retained with an installer notice. Access or
validation errors for the recognized recovery abort installation. A patch-level
downgrade or different Android major version is refused. The current scope is
this project's Android 14 OTA packages and the published FBE-capable TWRP build.
Manual partition flashing and third-party ROM installers do not run these hooks.

Synchronization writes one aligned 512-byte sector with only bytes 44..47
changed, fsyncs it, checks sector readback and rechecks the full image identity.
An error after writing triggers restoration and verification of the original
sector. An already aligned header needs no partition write. No key files,
userdata or encryption settings are read or modified by this helper.

The binary is statically linked to run in the existing Android 12.1 TWRP.
A narrowly scoped BoringSSL build-visibility entry permits its SHA-256-only
static dependency, as for the existing recovery updater. Cryptographic
algorithms, platform FIPS checks and Android SELinux policy are unchanged.

## Validation

Regular-file tests pass preflight/no-op behavior, September-to-October
synchronization, preservation of all other image bytes, downgrade/major/date
rejection, injected-write rollback and unknown/read-only/symlink/truncated-input
handling. OTA-hook tests pass full and incremental ordering, month/year
derivation and bad/missing-input rejection.

Run the tests against the separate device checkout (the integration repository
does not duplicate the device tree):

```sh
python3 lineage-21/tools/test-recovery-header-sync.py /path/to/recovery-twrp-sm-t510.img --source /path/to/device/recovery-header-sync/recovery_header_sync.cpp
python3 lineage-21/tools/test-recovery-header-releasetools.py --source /path/to/device/releasetools.py
```

The production ARM32 executable runs in the installed TWRP, recognizes its image
and completes an already-aligned no-op. Release verification passes 180 private
APK/APEX-container signatures, 30 APEX-payload signatures and the OTA whole-file
signature. The packaged helper/hooks match the built sources, the ARM32 binary
is static and excludes host fault-injection controls, preflight precedes
partition writes and synchronization follows the boot-image write. The original
kernel, stock vendor and DTBO checks pass. The OTA contains no data wipe.

The signed candidate 13 OTA was installed on the SM-T510 after setting only its
on-disk recovery OS word one month behind (August instead of September). The
running recovery retained its known-good September boot state and was never
rebooted with the deliberately old header. The OTA preflight accepted the known
image and its end hook corrected `0x1c0001a8` to `0x1c0001a9`. Readback verified
the entire 47,185,920-byte recovery partition matched the original backup,
including its unchanged payload and tail.

After a recovery reboot, the user entered the existing PIN successfully and
real credential-encrypted SQLite data was readable. All 15 original key files
were byte-identical. Android then booted build `gta3xlwifi.20261005.180749`, with
the existing home/apps confirmed by the user, all 210 package/UID records
preserved, FBE active, private release keys and SELinux enforcing. Current-boot
crash/ANR checks contain no markers. TWRP remains `3.7.1_12`.

ROM SHA-256: `94110cab46fa1edf908914dfbcc3c910ec5e5e16f306a810e13e673d3d5b597b`.
See the [scoped runtime report](recovery-header-sync-runtime-check.json),
[release verification](recovery-sync-release-signature-check.json) and
[package-hook audit](recovery-header-sync-package-check.json).
Monthly forward derivation is tested on regular-file fixtures (September to
October and next-year hook generation); the physical test used the current
September ROM and an older header. This validates the synchronization mechanism,
not compatibility with every future TEE/vendor or Android-major change.
