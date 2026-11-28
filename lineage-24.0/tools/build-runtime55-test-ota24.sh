#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Guarded non-A/B test OTA, standard public AOSP development key only.
# No device operations, recovery writes, data wipe, repartition or release signing.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$L/build.lock"; flock -n 9 || exit 75
[[ $(cat "$L/ota-tools-build-20261116-01.exit") == 0 && $(cat "$L/runtime55-product-checks-20261128-01.exit") == 0 ]] || exit 1
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
finish() {
 rc=$?; trap - EXIT
 if [[ -f $O/source-before.json && ! -f $O/source-after.json ]]; then
  python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261128-55" "$O/source-after.json" || rc=1
 fi
 printf '%s\n' "$rc" >"$L/$label.exit"
 exit "$rc"
}
trap finish EXIT
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261128-55" "$O/source-before.json"
(cd "$T" && sha256sum out/host/linux-x86/bin/ota_from_target_files) >"$O/tool.sha256"
printf '%s\n' 'ROM and packaging source: port-20261128-55 (build 55: snapshot54 plus the issue #6 boot-time file-system check fix: e2fsck ignores the Samsung kernel private-algorithm flag on encrypted files, so a forced check after an unclean shutdown no longer moves every encrypted file to lost+found and deletes the user keys; build 54: snapshot53 patches on lineage-24.0 synced 2026-11-27, and the network statistics journal closes its kernel boot-identity descriptor so system_server no longer runs out of file descriptors and restarts after about 3.7 days of uptime; build 53: snapshot52 plus SD-card storage, issue #4: adoptable volumes use the kernel-supported AES-256-XTS/AES-256-CTS fscrypt modes instead of the pre-Q AES-256-HEH default that F2FS rejects, adoptable storage offered through persist.sys.adoptable=force_on, and the kernel sdfat driver also registered as exfat so exFAT cards mount). Synced lineage-24.0 (2026-11-27) with NetworkStack legacy-backend data-stall fallback and scoped firmware_load for camera, codec, ueventd and the kernel audio-DSP loader, plus scoped ION read for cameraserver, the netpolicy flush descriptor-table kernel fix, scoped ION read for the permission dialog/mediaprovider/mediaserver, the HIDL-only Bluetooth audio shim, enabled Bluetooth A2DP/AVRCP/HID/PAN/OPP/BAS profiles, a legacy-backend network-rule wait so resumed apps do not run before their real unblock commit, log-noise corrections (iptables revision warning, fs-verity on a pre-R launch device, memfd readlink in sandboxes, quiet dm probe), and a fixed boot image header patch level (BOOT_SECURITY_PATCH 2026-11-01, matching the installed TWRP header) decoupled from the platform security patch, and recognition of the owner-approved TWRP image (newer system patch month accepted) in the read-only recovery preflight, and /product folded into /system (no product image; the physical product partition is not written) so GApps packages fit, and scoped ION read for privileged apps targeting SDK < 37 (priv_app_all) and Google Play services UI (gmscore_app), and the gate-split kernel/netd (normal policy updates keep the app packet gate open), and OTA updates through the built-in LineageOS Updater (lineage.updater.uri on GitHub, addon.d backup/restore with vendor/product write-protected), and recognition of the owner-approved TWRP 33875693 (fstab without /product, ABGR colour), and an unattended-install step that stops the TWRP FBE helper services and unmounts vendor before the unchanged vendor-unmounted guard, and a TWRP-RAM /product -> system/product link so backuptool keeps addon.d (GApps) packages, and scoped ION read for the LineageOS Updater (updater_app) so its UI renders, and parceling of immutable bitmaps above 12 KiB through read-only ashmem when the kernel lacks memfd F_SEAL_FUTURE_WRITE (fixes F-Droid session installs and other icon/bitmap binder transfers), and the Updater Recent changes button opening the GitHub releases (with changelogs) instead of the missing download.lineageos.org page, and boot image/odex compiled for the read-barrier (concurrent-copying) GC so framework and app code runs AOT instead of interpreted/JIT, and a touch/launch CPU-GPU boost that recovers after a control open/write failure (backoff 1-60 s, reason logged to main and system), and network statistics rows without an interface name skipped as in Android 17 (no system_server crash loop on Wi-Fi), and SD-card storage: adoptable volumes with kernel-supported fscrypt modes, adoptable storage offered for SD cards and USB disks, and exFAT cards mounted by the kernel sdfat driver.' >"$O/provenance.txt"
archive=$T/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
cp --reflink=auto "$archive" "$O/target-files.zip"
python3 - "$O/target-files.zip" "$A/runtime55-product-checks-20261128-01/geometry-policy.json" <<'PY'
import hashlib,json,sys
from pathlib import Path
f=Path(sys.argv[1]);r=json.load(open(sys.argv[2]));h=hashlib.sha256()
with f.open('rb') as src:
 for b in iter(lambda:src.read(1024*1024),b''):h.update(b)
assert r['artifact_checks_passed'] and h.hexdigest()==r['archive_sha256']
PY
cd "$T"
# Name the package after the actual build date (ro.build.date.utc, UTC), as LineageOS does.
name=$(python3 - "$O/target-files.zip" <<'PY'
import datetime,sys,zipfile
z=zipfile.ZipFile(sys.argv[1])  # ro.lineage.* are in the product build.prop (product folded into system)
p=dict(l.split('=',1) for f in ['SYSTEM/build.prop','SYSTEM/product/etc/build.prop'] for l in z.read(f).decode().splitlines() if '=' in l and not l.startswith('#'))
assert p['ro.lineage.build.version']=='24.0' and p['ro.lineage.releasetype']=='UNOFFICIAL'
d=datetime.datetime.fromtimestamp(int(p['ro.build.date.utc']),datetime.timezone.utc).strftime('%Y%m%d')
print('lineage-24.0-%s-UNOFFICIAL-gta3xlwifi-test.zip'%d)
PY
)
[[ $name =~ ^lineage-24\.0-20[0-9]{6}-UNOFFICIAL-gta3xlwifi-test\.zip$ ]] || exit 1
# Standard non-A/B OTA; addon.d backup/restore is emitted by releasetools.py (not --backup).
out/host/linux-x86/bin/ota_from_target_files -v -k build/make/target/product/security/testkey -p out/host/linux-x86 "$O/target-files.zip" "$O/$name"
(cd "$O" && sha256sum "$name") >"$O/SHA256SUMS"
printf '%s\n' 'GUARDED TEST CANDIDATE. Requires successful package checks and existing recognized recovery with exactly matching Android17 OS/SPL. Header matching is NOT FBE/runtime proof. Owner authorized this physical test; package verification must finish before installation.' >"$O/TEST_CANDIDATE_STATUS.txt"
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261128-55" "$O/source-after.json"
