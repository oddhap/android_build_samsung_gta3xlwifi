#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Isolated production policy compilation; no ROM, signing or device access.
set -eo pipefail
port=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
label=${1:?Usage: build-user-policy-maps.sh NEW_LABEL}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$logs/build.lock"
flock -n 9 || { echo 'Another build/validation is active.' >&2; exit 1; }
[[ ! -e $logs/$label.exit && ! -e $artifacts/$label ]] || exit 1
mkdir "$artifacts/$label"
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; date -u +%FT%TZ > "$artifacts/$label/finished-at.txt"; exit "$rc"' EXIT
source "$port/env.sh"
[[ $PWD == /srv/android/src/lineage-24.0-arm64 ]] || exit 1
export OUT_DIR=out-policy-user-20261101-01
[[ -d $OUT_DIR && ! -L $OUT_DIR ]] || exit 1
[[ $(cat "$logs/policy-user-20261101-01.exit") == 0 ]] || exit 1
python3 - "$artifacts/policy-user-20261101-01/source-audit-after.json" <<'PY_CHECK'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['passed'] and r['project_count']==1243 and r['reviewed_patch_count']==15
PY_CHECK
snapshot="$port/lineage-24.0/snapshots/port-20261101-05"
python3 "$port/lineage-24.0/tools/audit-port.py" "$PWD" "$snapshot" "$artifacts/$label/source-audit-before.json"
source build/envsetup.sh
lunch lineage_gta3xlwifi aosp_current user
[[ $(get_build_var TARGET_BUILD_VARIANT) == user ]] || exit 1
[[ $(get_build_var OUT_DIR) == "$OUT_DIR" ]] || exit 1
printf '%s\n' "$OUT_DIR" > "$artifacts/$label/out-dir.txt"
date -u +%FT%TZ > "$artifacts/$label/started-at.txt"
m -j16 selinux_policy plat_30.0.cil 30.0.compat.cil system_ext_30.0.cil system_ext_30.0.compat.cil product_30.0.cil
python3 "$port/lineage-24.0/tools/audit-port.py" "$PWD" "$snapshot" "$artifacts/$label/source-audit-after.json"
