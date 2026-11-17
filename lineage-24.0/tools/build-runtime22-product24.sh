#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Full product target-files build with an explicitly selected kernel/vendor pair. No OTA, release signing or device operations.
set -eo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64
label=${1:?Usage: build-runtime22-product24.sh NEW_LABEL INPUT_SELECTION_REPORT}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
selection=${2:?Input selection report required}
[[ $selection == /srv/android/artifacts/lineage-24.0-arm64/*/report.json && -f $selection ]] || exit 2
snapshot=$ports/lineage-24.0/snapshots/port-20261117-22
exec 9>"$logs/build.lock"
flock -n 9 || exit 75
[[ ! -e $art/$label && ! -e $logs/$label.exit ]] || exit 2
mkdir "$art/$label"
exec >"$logs/$label.log" 2>&1
finish() {
 rc=$?; trap - EXIT
 if [[ -f $art/$label/source-before.json && ! -f $art/$label/source-after.json ]]; then
  python3 "$ports/lineage-24.0/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$snapshot" "$art/$label/source-after.json" || rc=1
 fi
 printf '%s\n' "$rc" >"$logs/$label.exit"
 date -u +%FT%TZ >"$art/$label/finished-at.txt"
 exit "$rc"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
source "$ports/env.sh"
[[ $PWD == /srv/android/src/lineage-24.0-arm64 ]] || exit 1
python3 "$ports/lineage-24.0/tools/audit-port.py" "$PWD" "$snapshot" "$art/$label/source-before.json"
python3 - "$selection" "$PWD" "$art/$label/inputs-before.json" <<'PY_CHECK'
import hashlib,json,sys
from pathlib import Path
f,T,O=map(Path,sys.argv[1:]);r=json.loads(f.read_text());assert r['passed'] and r['original_rollback_copies_verified']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert {n:sha(T/'device/samsung/gta3xlwifi/prebuilt'/n) for n in r['after']}==r['after']
O.write_text(json.dumps({'selection_report_sha256':sha(f),'prebuilts':r['after']},indent=2)+'\n')
PY_CHECK
source build/envsetup.sh
lunch lineage_gta3xlwifi aosp_current userdebug
printf '%s\n' target-files-package >"$art/$label/targets.txt"
date -u +%FT%TZ >"$art/$label/started-at.txt"
m -j12 target-files-package
python3 - "$selection" "$PWD" "$art/$label/inputs-after.json" <<'PY_CHECK'
import hashlib,json,sys
from pathlib import Path
f,T,O=map(Path,sys.argv[1:]);r=json.loads(f.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert {n:sha(T/'device/samsung/gta3xlwifi/prebuilt'/n) for n in r['after']}==r['after']
O.write_text(json.dumps({'selection_report_sha256':sha(f),'prebuilts':r['after']},indent=2)+'\n')
PY_CHECK
