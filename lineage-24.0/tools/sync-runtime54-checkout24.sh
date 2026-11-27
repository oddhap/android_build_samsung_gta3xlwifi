#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Snapshot54 step 2 (owner request 2026-11-27: newest lineage-24.0 sources):
# reverse-apply the 24 exact snapshot53 patches (proved by the
# runtime54-sync-fetch audit and the runtime54 patch dry-run), check out the
# fetched lineage-24.0 revisions locally, keep the device/kernel/vendor trees
# at their pinned snapshot53 revisions, re-apply every patch unchanged and
# capture/audit the new locked snapshot. Any failure stops; snapshot53 stays
# reproducible from its manifest, patches and the saved manifest state.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
S53=$P/snapshots/port-20261123-53
S54=$P/snapshots/port-20261127-54-sync
fetch=${FETCH_LABEL:?FETCH_LABEL required}
dryrun=${DRYRUN_LABEL:?DRYRUN_LABEL required}
label=${1:?Fresh label required}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$L/build.lock"; flock -n 9 || exit 75
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit && ! -e $S54 ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
export PATH="$HOME/bin:$PATH" LC_ALL=C.UTF-8 LANG=C.UTF-8
[[ $(cat "$L/$fetch.exit") == 0 ]]
python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));assert r["passed"]' "$A/$fetch/source-before-sync.json"
python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));assert r["all_clean"]' "$A/$dryrun/report.json"
mapfile -t projects < <(python3 -c 'import json,sys;[print(r["project"]) for r in json.load(open(sys.argv[1]))]' "$S53/source-lock.json")
mapfile -t patches < <(python3 -c 'import json,sys;[print(r["patch"]) for r in json.load(open(sys.argv[1]))]' "$S53/source-lock.json")
cd "$T"
# 1. Prove each patched tree still equals its exact patch, then reverse it.
for i in "${!projects[@]}"; do
  p=${projects[$i]}; f=$S53/patches/${patches[$i]}
  cmp -s "$f" <(git -C "$p" diff --binary --no-ext-diff --full-index HEAD)
  [[ -z $(git -C "$p" ls-files --others --exclude-standard) ]]
  git -C "$p" apply --reverse "$f"
  git -C "$p" reset -q
  [[ -z $(git -C "$p" status --porcelain --untracked-files=normal) ]]
done
echo "PASS reversed ${#projects[@]} exact snapshot53 patches"
# 2. Own trees stay pinned at their snapshot53 revisions (local manifest unchanged).
dev=$(python3 -c 'import json,sys;print([r["revision"] for r in json.load(open(sys.argv[1])) if r["project"]=="device/samsung/gta3xlwifi"][0])' "$S53/source-lock.json")
grep -q "revision=\"$dev\"" .repo/local_manifests/gta3xlwifi.xml
cp -p .repo/local_manifests/gta3xlwifi.xml "$O/gta3xlwifi.xml"
# 3. Local checkout only (objects already fetched).
repo sync -l -j8 --no-tags
# 4. Re-apply every reviewed patch unchanged.
for i in "${!projects[@]}"; do
  git -C "${projects[$i]}" apply --index "$S53/patches/${patches[$i]}"
done
echo "PASS re-applied ${#projects[@]} unchanged patches on current lineage-24.0"
python3 "$P/tools/capture-port.py" --parent-snapshot "$S53" "$T" "$S54" "${projects[@]}"
python3 "$P/tools/audit-port.py" "$T" "$S54" "$O/source-after-checkout.json"
(cd "$T" && repo manifest -r -o "$O/resolved-after-checkout.xml")
python3 - "$S53" "$S54" "$O" <<'PY'
import json,sys
from pathlib import Path
a,b,o=map(Path,sys.argv[1:])
old={r['project']:r for r in json.loads((a/'source-lock.json').read_text())}
new={r['project']:r for r in json.loads((b/'source-lock.json').read_text())}
assert old.keys()==new.keys()
same=[p for p in old if (a/'patches'/old[p]['patch']).read_bytes()==(b/'patches'/new[p]['patch']).read_bytes()]
moved=sorted(p for p in old if old[p]['revision']!=new[p]['revision'])
(o/'report.json').write_text(json.dumps({'passed':True,'snapshot':str(b),
 'patches':len(new),'byte_identical_patches':len(same),
 'rebased_patches':sorted(set(old)-set(same)),'patched_projects_moved':moved},indent=2)+'\n')
print('PASS snapshot54-sync captured;',len(same),'of',len(new),'patch files byte-identical; moved:',moved)
PY
