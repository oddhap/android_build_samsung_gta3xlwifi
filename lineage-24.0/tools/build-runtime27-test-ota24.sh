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
[[ $(cat "$L/ota-tools-build-20261116-01.exit") == 0 && $(cat "$L/runtime27-product-checks-20261118-03.exit") == 0 ]] || exit 1
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
finish() {
 rc=$?; trap - EXIT
 if [[ -f $O/source-before.json && ! -f $O/source-after.json ]]; then
  python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261118-27" "$O/source-after.json" || rc=1
 fi
 printf '%s\n' "$rc" >"$L/$label.exit"
 exit "$rc"
}
trap finish EXIT
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261118-27" "$O/source-before.json"
(cd "$T" && sha256sum out/host/linux-x86/bin/ota_from_target_files) >"$O/tool.sha256"
printf '%s\n' 'ROM and packaging source: port-20261118-27. Includes minimum backlight mapping and legacy keyboard rendering compatibility.' >"$O/provenance.txt"
archive=$T/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
cp --reflink=auto "$archive" "$O/target-files.zip"
python3 - "$O/target-files.zip" "$A/runtime27-product-checks-20261118-03/geometry-policy.json" <<'PY'
import hashlib,json,sys
from pathlib import Path
f=Path(sys.argv[1]);r=json.load(open(sys.argv[2]));h=hashlib.sha256()
with f.open('rb') as src:
 for b in iter(lambda:src.read(1024*1024),b''):h.update(b)
assert r['artifact_checks_passed'] and h.hexdigest()==r['archive_sha256']
PY
cd "$T"
out/host/linux-x86/bin/ota_from_target_files -v -k build/make/target/product/security/testkey -p out/host/linux-x86 "$O/target-files.zip" "$O/lineage-24.0-20261118-UNOFFICIAL-gta3xlwifi-test.zip"
sha256sum "$O/lineage-24.0-20261118-UNOFFICIAL-gta3xlwifi-test.zip" >"$O/SHA256SUMS"
printf '%s\n' 'GUARDED TEST CANDIDATE. Requires successful package checks and existing recognized recovery with exactly matching Android17 OS/SPL. Header matching is NOT FBE/runtime proof. Owner authorized this physical test; package verification must finish before installation.' >"$O/TEST_CANDIDATE_STATUS.txt"
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261118-27" "$O/source-after.json"
