#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Snapshot31 step 2: reverse-apply the 23 exact snapshot29 patches (proved by
# the runtime31-sync-fetch-20261120-01 audit and patch dry-run), check out the
# fetched lineage-24.0 revisions locally, keep the device tree at its
# snapshot29 revision, re-apply every patch unchanged and capture/audit the new
# locked snapshot. Any failure stops; snapshot29 stays reproducible from its
# manifest, patches and the saved manifest state.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
S29=$P/snapshots/port-20261118-29
S31=$P/snapshots/port-20261120-31-sync
label=${1:?Fresh label required}
exec 9>"$L/build.lock"; flock -n 9 || exit 75
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit && ! -e $S31 ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
export PATH="$HOME/bin:$PATH" LC_ALL=C.UTF-8 LANG=C.UTF-8
[[ $(cat "$L/runtime31-sync-fetch-20261120-01.exit") == 1 ]]   # audit PASS, fetch stopped
grep -q '^PASS: 1243 locked projects, 23 exact' "$L/runtime31-sync-fetch-20261120-01.log"
python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));assert r["all_clean"]' \
  "$A/runtime31-patch-dryrun-20261120-01/report.json"
mapfile -t projects < <(python3 -c 'import json,sys;[print(r["project"]) for r in json.load(open(sys.argv[1]))]' "$S29/source-lock.json")
mapfile -t patches < <(python3 -c 'import json,sys;[print(r["patch"]) for r in json.load(open(sys.argv[1]))]' "$S29/source-lock.json")
cd "$T"
# 1. Prove each patched tree still equals its exact patch, then reverse it.
for i in "${!projects[@]}"; do
  p=${projects[$i]}; f=$S29/patches/${patches[$i]}
  cmp -s "$f" <(git -C "$p" diff --binary --no-ext-diff --full-index HEAD)
  [[ -z $(git -C "$p" ls-files --others --exclude-standard) ]]
  git -C "$p" apply --reverse "$f"
  git -C "$p" reset -q
  [[ -z $(git -C "$p" status --porcelain --untracked-files=normal) ]]
done
echo "PASS reversed ${#projects[@]} exact snapshot29 patches"
# 2. Device tree stays at the snapshot29 revision (descendant of the old pin).
dev=$(python3 -c 'import json,sys;print([r["revision"] for r in json.load(open(sys.argv[1])) if r["project"]=="device/samsung/gta3xlwifi"][0])' "$S29/source-lock.json")
git -C device/samsung/gta3xlwifi merge-base --is-ancestor 2f649d06fec3318926c61aaf7a5fa3f40aa9f266 "$dev"
sed -i "s/2f649d06fec3318926c61aaf7a5fa3f40aa9f266/$dev/" .repo/local_manifests/gta3xlwifi.xml
cp -p .repo/local_manifests/gta3xlwifi.xml "$O/gta3xlwifi.xml"
# 3. Local checkout only (objects already fetched).
repo sync -l -j8 --no-tags
# 4. Re-apply every reviewed patch unchanged.
for i in "${!projects[@]}"; do
  git -C "${projects[$i]}" apply --index "$S29/patches/${patches[$i]}"
done
echo "PASS re-applied ${#projects[@]} unchanged patches on current lineage-24.0"
python3 "$P/tools/capture-port.py" --parent-snapshot "$S29" "$T" "$S31" "${projects[@]}"
python3 "$P/tools/audit-port.py" "$T" "$S31" "$O/source-after-checkout.json"
python3 - "$S29" "$S31" "$O" <<'PY'
import json,sys,hashlib
from pathlib import Path
a,b,o=map(Path,sys.argv[1:])
old={r['project']:r for r in json.loads((a/'source-lock.json').read_text())}
new={r['project']:r for r in json.loads((b/'source-lock.json').read_text())}
assert old.keys()==new.keys()
same=[p for p in old if (a/'patches'/old[p]['patch']).read_bytes()==(b/'patches'/new[p]['patch']).read_bytes()]
(o/'report.json').write_text(json.dumps({'passed':True,'snapshot':str(b),
 'patches':len(new),'byte_identical_patches':len(same),
 'rebased_patches':sorted(set(old)-set(same))},indent=2)+'\n')
print('PASS snapshot31-sync captured;',len(same),'of',len(new),'patch files byte-identical')
PY
