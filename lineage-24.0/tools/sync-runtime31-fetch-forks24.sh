#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Snapshot31 step 1b: the 2026-11 ASB moved 12 unpatched projects from AOSP to
# LineageOS forks. Re-link only those (proved clean and unpatched by the step-1
# audit) with --force-sync, then fetch everything network-only (repo sync -n).
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
exec 9>"$L/build.lock"; flock -n 9 || exit 75
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
export PATH="$HOME/bin:$PATH" LC_ALL=C.UTF-8 LANG=C.UTF-8
forks=(external/aac external/hplip external/libopenapv external/tremolo hardware/broadcom/wlan
 packages/apps/ManagedProvisioning packages/modules/IntentResolver packages/modules/NeuralNetworks
 packages/modules/Profiling packages/services/Iwlan system/gsid trusty/user/base)
python3 - "$P/snapshots/port-20261118-29/source-lock.json" "${forks[@]}" <<'PY'
import json,sys
patched={r['project'] for r in json.load(open(sys.argv[1]))}
assert not patched & set(sys.argv[2:]), patched & set(sys.argv[2:])
PY
cd "$T"
for f in "${forks[@]}"; do
  if [[ -d $f ]]; then
    [[ -z $(git -C "$f" status --porcelain --untracked-files=normal) ]] || { echo "dirty $f"; exit 3; }
    git -C "$f" rev-parse HEAD >>"$O/fork-heads-before.txt"
  fi
done
repo sync -n -j8 --no-clone-bundle --no-tags --force-sync "${forks[@]}"
repo sync -n -j8 --no-clone-bundle --no-tags --fail-fast
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261118-29" "$O/source-after-fetch.json"
echo 'PASS network-only fetch; checkout still equals snapshot29'
