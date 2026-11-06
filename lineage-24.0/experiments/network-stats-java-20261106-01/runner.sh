#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
source /srv/android/ports/lineage-24.0-arm64/env.sh
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=network-stats-java-20261106-01
art=/srv/android/artifacts/lineage-24.0-arm64/$label
snapshot="$port/snapshots/port-20261106-02"
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
[[ ! -e $art && ! -e $logs/$label.exit ]]
exec >"$logs/$label.log" 2>&1
finish() {
 rc=$?
 trap - EXIT
 if [[ -d $art ]]; then
  python3 "$port/tools/audit-port.py" "$top" "$snapshot" "$art/source-after.json" || rc=1
 fi
 printf '%s\n' "$rc" > "$logs/$label.exit"
 exit "$rc"
}
trap finish EXIT
[[ $(cat "$logs/init-data-preservation-native-20261106-01.exit") == 0 ]]
mkdir "$art"; cp "$port/experiments/network-stats-java-20261106-01/build-isolated.sh" "$art/runner.sh"
python3 "$port/tools/audit-port.py" "$top" "$snapshot" "$art/source-before.json"
python3 "$port/tools/compile-qtaguid-java24.py" --top "$top" --staging /srv/android/ports/lineage-24.0-arm64/statsjava24-20261106-01 --lock "$port/experiments/network-stats-java-20261106-01/source-lock.json" --output "$art/java"
