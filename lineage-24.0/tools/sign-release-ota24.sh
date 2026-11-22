#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# PREPARED, NOT YET VALIDATED: release-key signing of a checked SM-T510 target-files
# package and generation of a release-signed OTA (owner approved key creation
# 2026-11-21; keys live only in $K on the build server and are never copied).
#
#   sign-release-ota24.sh NEW_LABEL CHECKED_OTA_BUILD_LABEL --i-approve-release-signing
#
# Steps (each stops on failure; nothing is written outside $A/NEW_LABEL):
#  1. take target-files.zip from a finished, fully checked test-OTA build
#     ($A/CHECKED_OTA_BUILD_LABEL with readiness-report.json passing);
#  2. sign_target_files_apks: AOSP dev keys -> owner keys (-d), networkstack/
#     sdk_sandbox/bluetooth/nfc (-k), every APEX container and payload key from
#     apex-names.txt, and -o (otacerts.zip = releasekey only);
#  3. require IMAGES/boot.img and IMAGES/vendor.img byte-identical to the input
#     (the port's boot-SPL/kernel and exact-vendor guards stay valid);
#  4. ota_from_target_files -k releasekey (same releasetools hooks/guards);
#  5. verify the whole-file signature with the PUBLIC release certificate.
#
# Before the first real release: run the port's package checks on the signed
# target-files/OTA (adapted to otacerts = release key), and test physically.
# Moving a device from test-key to release-key APK signatures changes the
# platform/shared/media certificates seen by PackageManager; do the first switch
# by sideload with a data backup (a data wipe may be needed). Later release-signed
# OTAs then install through the Updater, which verifies them against otacerts.
set -euo pipefail
label=${1:?NEW_LABEL}; source_label=${2:?CHECKED_OTA_BUILD_LABEL}
[[ ${3:-} == --i-approve-release-signing ]] || { echo 'Owner approval flag missing' >&2; exit 2; }
[[ $label =~ ^[a-zA-Z0-9_-]+$ && $source_label =~ ^runtime[0-9]+-ota-build-[0-9]{8}-[0-9]{2}$ ]] || exit 2
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
K=/srv/android/keys/lineage-24.0-gta3xlwifi
exec 9>"$L/build.lock"; flock -n 9 || exit 75
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
[[ $(stat -c %a "$K") == 700 && -f $K/releasekey.pk8 && -f $K/apex-names.txt ]] || exit 1
mkdir "$O"; chmod 755 "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
S=$A/$source_label
python3 - "$S/readiness-report.json" "$S/target-files.zip" <<'PY'
import hashlib,json,sys
r=json.load(open(sys.argv[1]));h=hashlib.sha256()
with open(sys.argv[2],'rb') as f:
 for b in iter(lambda:f.read(1<<20),b''):h.update(b)
assert r['technical_package_checks_passed'] and r['target_files_sha256']==h.hexdigest()
PY
apex_args=()
while read -r a; do
  [[ $a =~ ^[a-zA-Z0-9._]+$ ]] || exit 1
  apex_args+=(--extra_apks "$a.apex=$K/$a" --extra_apex_payload_key "$a.apex=$K/$a.pem")
done <"$K/apex-names.txt"
cd "$T"
sec=build/make/target/product/security
out/host/linux-x86/bin/sign_target_files_apks -o -d "$K" \
  -k "$sec/networkstack=$K/networkstack" -k "$sec/sdk_sandbox=$K/sdk_sandbox" \
  -k "$sec/bluetooth=$K/bluetooth" -k "$sec/nfc=$K/nfc" \
  "${apex_args[@]}" "$S/target-files.zip" "$O/signed-target-files.zip"
# sign_target_files_apks drops the prebuilt images it cannot rebuild (no VENDOR/ tree):
# put back exactly IMAGES/vendor.img and IMAGES/cache.img from the checked archive.
python3 - "$S/target-files.zip" "$O/signed-target-files.zip" <<'PY'
import sys,zipfile
src,dst=sys.argv[1:]
with zipfile.ZipFile(src) as a,zipfile.ZipFile(dst) as b:missing=sorted(set(a.namelist())-set(b.namelist()))
assert set(missing)<={'IMAGES/vendor.img','IMAGES/cache.img'},missing
with zipfile.ZipFile(src) as a,zipfile.ZipFile(dst,'a',allowZip64=True) as b:
 for n in missing:
  i=a.getinfo(n);b.writestr(i,a.read(n),compress_type=i.compress_type)
print('restored',missing)
PY
python3 - "$S/target-files.zip" "$O/signed-target-files.zip" "$K/releasekey.x509.pem" <<'PY'
import io,sys,zipfile
a,b=zipfile.ZipFile(sys.argv[1]),zipfile.ZipFile(sys.argv[2])
for n in ['IMAGES/boot.img','IMAGES/vendor.img']:
 assert a.read(n)==b.read(n),n+' changed by signing'
certs=zipfile.ZipFile(io.BytesIO(b.read('SYSTEM/etc/security/otacerts.zip')))
assert [certs.read(x) for x in certs.namelist()]==[open(sys.argv[3],'rb').read()],'otacerts is not the release key only'
assert not any(n.endswith(('.pk8','.key')) for n in b.namelist())
PY
name=$(basename "$(ls "$S"/lineage-24.0-20??????-UNOFFICIAL-gta3xlwifi-test.zip)" -test.zip).zip
out/host/linux-x86/bin/ota_from_target_files -v -k "$K/releasekey" -p out/host/linux-x86 "$O/signed-target-files.zip" "$O/$name"
cp "$K/releasekey.x509.pem" "$O/releasekey.x509.pem"
(cd "$O" && sha256sum "$name") >"$O/SHA256SUMS"
printf '%s\n' 'RELEASE-SIGNED CANDIDATE (owner keys). Not yet covered by the port package checks; physical test required.' >"$O/STATUS.txt"
