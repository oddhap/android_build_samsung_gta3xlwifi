# Native LineageOS 21 port for SM-T510

This is Android 14, ARM32 userspace with the existing ARM64 Samsung kernel.
It does not use a GSI, Google services, dynamic partitions or an A/B conversion.
The current platform source reports the 2026-09-01 security patch level. That
does not imply that the old Samsung kernel/vendor firmware has the same fixes.

The build uses an independent Ubuntu 22.04 checkout at
`/srv/android/src/lineage-21.0`. Preserve the working Android 12 checkout,
installation ZIP and tested TWRP recovery as rollback inputs.

## Reproduce the platform changes

Copy this integration directory to `/srv/android/ports/lineage-21`.
The original source manifest is saved in `notes/lineage-21.0-source-manifest.xml`.
`notes/pinned-build-manifest.xml` has identical project revisions and absolute
remote URLs so that a standalone local manifest can be used in a fresh checkout.
Run `bash tools/sync-pinned-platform.sh` only against an empty checkout.

Stage the device repository into `device/samsung/gta3xlwifi`. Run
`python3 tools/stage-native-device.py` after restoring the verified baseline
inputs under `/srv/android`: `vendor-stock/images`, extracted CWA1 vendor files,
and the original source-built `artifacts/kernel-smoke` kernel/config/DTBOs.
`python3 tools/fetch-baseline-kernel.py` downloads and checks the exact baseline
kernel inputs from the private `lineage21-baseline-kernel` release. Existing
different inputs are rejected. GitHub CLI must be authenticated to the account.
The device repository excludes large prebuilt inputs; staging checks their
checksums. The baseline kernel build tools and private vendor release are in
the existing integration/kernel/vendor repositories. Do not use the rejected
ramdisk experiment under `notes/rejected-ramdisk-research`.

Run `python3 tools/apply-pinned-patches.py` to apply the six final platform
patches. It checks every revision, patch checksum and application before writing
source. `--check-only` verifies the current tree without modifying it.
The incremental development helpers are retained for review; they are not
additional patches to apply after the final exported patches.

Build with `bash tools/build-rom.sh bacon`. It selects
`lineage_gta3xlwifi-ap2a-userdebug` and retains a single build timestamp across
incremental retries. The original kernel, stock vendor and physical system root
are preserved. The optional network probe has `installable: false` and is not
part of the product package list.

## Verify before a hardware installation

Capture the build's exit code in `/srv/android/logs/lineage21-rom-build-final.exit`.
Run `verify-native-images.py`, `verify-native-layout.py`, `verify-port-package.py`, `check-native-vintf.py`
and `check-stock-vendor-policy.py --runtime-mode`. The image verifier checks the
expanded sizes, boot headers, Samsung trailers, original kernel/vendor/DTBO,
recovery layout and OTA metadata. The package verifier checks the Android
version, packaged power backend, networking selector, absence of the probe and
Google service APKs, and OTA partition references.

Generated platform SELinux tests remain enabled. Actual stock vendor CIL links
with Android init's normal runtime flags while SELinux remains enforcing. A
separate strict cross-version neverallow diagnostic fails on the old Samsung
vendor policy; the Android 12 baseline fails that diagnostic too. This is a
remaining vendor limitation, not proof of full security equivalence.

## Evidence and remaining physical tests

Host tests cover real firewall policy generation and rollback state, and Samsung
qtaguid parsing/error behavior with mocked boundaries. The optional ARM32 packet
probe installs IPv4/IPv6 rules on the tablet's original kernel and verifies real
IPv4 allow/deny packets in scoped private chains. It cleans its own chains and
the test UID/UDP hook. IPv6 packets have not been exercised. These tests ran on
Android 12 and do not demonstrate Android 14 Binder or service operation.

Before calling the port usable, verify Android 14 boots with SELinux enforcing,
both cameras, rotation, Wi-Fi/reconnect, browser video/audio, charging, USB/ADB,
sleep/wake and overnight idle. Check actual DNS, per-app data usage, data saver
and always-on VPN lockdown. Verify CPU/GPU boost resets after its bounded window
and during screen-off/battery saver. Encryption and recovery interaction also
need physical validation. Do not label the build stable until these tests pass.
