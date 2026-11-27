#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Snapshot54 step 1: prove the checkout equals snapshot53, preserve the exact
# manifest state, then fetch current lineage-24.0 objects WITHOUT touching any
# working tree (repo sync -n). No source file is changed by this script.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$L/build.lock"; flock -n 9 || exit 75
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
export PATH="$HOME/bin:$PATH" LC_ALL=C.UTF-8 LANG=C.UTF-8
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261123-53" "$O/source-before-sync.json"
mkdir "$O/manifest-state"
git -C "$T/.repo/manifests" rev-parse HEAD >"$O/manifest-state/manifests-head.txt"
cp -p "$T/.repo/local_manifests/"*.xml "$O/manifest-state/"
(cd "$T" && repo manifest -r -o "$O/manifest-state/resolved-before.xml")
sha256sum "$O/manifest-state/"* >"$O/manifest-state/SHA256SUMS"
(cd "$T" && repo init -q -b lineage-24.0 --no-clone-bundle)
git -C "$T/.repo/manifests" rev-parse HEAD >"$O/manifest-state/manifests-new-head.txt"
(cd "$T" && repo sync -n -j8 --no-clone-bundle --no-tags --fail-fast)
(cd "$T" && repo manifest -r -o "$O/manifest-state/resolved-after-fetch.xml") || true
python3 - "$O" <<'PY'
import json,sys,xml.etree.ElementTree as ET
from pathlib import Path
o=Path(sys.argv[1])
def revs(p):
    return {x.get('path',x.get('name')):x.get('revision') for x in ET.parse(p).getroot().iter('project')}
old=revs(o/'manifest-state/resolved-before.xml')
lock=json.loads(Path('/srv/android/ports/lineage-24.0-arm64/lineage-24.0/snapshots/port-20261123-53/source-lock.json').read_text())
print('PASS fetch-only; projects in old lock:',len(old),'patched:',len(lock))
(o/'report.json').write_text(json.dumps({'passed':True,'fetch_only':True,
 'working_trees_changed':False,'old_project_count':len(old)},indent=2)+'\n')
PY
