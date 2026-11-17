#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Actual selected source policy compilation. No OTA, release signing or device operations.
set -eo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64
label=${1:?Usage: build-policy-composition24.sh NEW_LABEL}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
snapshot=$ports/lineage-24.0/snapshots/port-20261117-15
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
source build/envsetup.sh
lunch lineage_gta3xlwifi aosp_current userdebug
printf '%s\n' selinux_policy plat_30.0.cil 30.0.compat.cil system_ext_30.0.cil system_ext_30.0.compat.cil product_30.0.cil >"$art/$label/targets.txt"
date -u +%FT%TZ >"$art/$label/started-at.txt"
m -j12 selinux_policy plat_30.0.cil 30.0.compat.cil system_ext_30.0.cil system_ext_30.0.compat.cil product_30.0.cil
