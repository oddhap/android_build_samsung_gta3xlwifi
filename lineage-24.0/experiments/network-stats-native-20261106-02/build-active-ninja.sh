#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Resolve the exact private Java artifact in the existing audited Soong graph.
set -euo pipefail
source /srv/android/ports/lineage-24.0-arm64/env.sh
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=network-stats-active-20261106-02
art=/srv/android/artifacts/lineage-24.0-arm64/$label
snapshot="$port/snapshots/port-20261106-03"
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
[[ ! -e $art && ! -e $logs/$label.exit ]]
exec >"$logs/$label.log" 2>&1
finish(){
 rc=$?; trap - EXIT
 if [[ -d $art ]]; then
  python3 "$port/tools/audit-port.py" "$top" "$snapshot" "$art/source-audit-after.json" || rc=1
 fi
 printf '%s\n' "$rc" > "$logs/$label.exit"
 date -u +%FT%TZ > "$art/finished-at.txt"
 exit "$rc"
}
trap finish EXIT
[[ $(cat "$logs/network-stats-active-20261106-01.exit") == 1 ]]
grep -Fq 'unknown target "service-connectivity-tiramisu-pre-jarjar"' "$logs/network-stats-active-20261106-01.log"
mkdir "$art"; cp "$port/experiments/network-stats-native-20261106-02/build-active-ninja.sh" "$art/runner.sh"
python3 "$port/tools/audit-port.py" "$top" "$snapshot" "$art/source-audit-before.json"
python3 - "$art" <<'PY'
from pathlib import Path
import hashlib,json,sys
A=Path(sys.argv[1]);source=A/'source-audit-before.json';previous=A.with_name('network-stats-active-20261106-01')
(previous/'post-failure-audit-reference.json').write_text(json.dumps({'source_audit':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'source_unchanged_after_target_resolution_failure':True,'no_source_edits_or_build_between_failure_and_this_audit':True},indent=2)+'\n')
PY
java=out/soong/.intermediates/packages/modules/Connectivity/service-t/service-connectivity-tiramisu-pre-jarjar/android_common_apex31/javac/service-connectivity-tiramisu-pre-jarjar.jar
printf '%s\n' libnetworkstats "$java" > "$art/targets.txt"
sha256sum out/combined-lineage_gta3xlwifi.ninja > "$art/graph.sha256"
date -u +%FT%TZ > "$art/started-at.txt"
prebuilts/build-tools/linux-x86/bin/ninja -f out/combined-lineage_gta3xlwifi.ninja -j16 -d keepdepfile -d keeprsp libnetworkstats "$java"
echo 'Actual Soong-generated module graph completed; no source edits or skipped compile/link checks.'
