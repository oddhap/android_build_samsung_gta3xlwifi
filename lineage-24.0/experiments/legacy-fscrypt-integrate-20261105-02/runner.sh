#!/usr/bin/env bash
# Device-scoped source integration only; no image promotion/signing/device access.
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=${1:-legacy-fscrypt-integrate-20261105-02}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
art=/srv/android/artifacts/lineage-24.0-arm64/$label
parent="$port/snapshots/port-20261103-07"
next="$port/snapshots/port-20261105-01"
proposal="$port/experiments/legacy-fscrypt-20261105-02"
source /srv/android/ports/lineage-24.0-arm64/env.sh
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
[[ ! -e $art && ! -e $next && ! -e $logs/$label.exit ]]
mkdir "$art"
cp "$proposal/apply-snapshot.sh" "$art/runner.sh"
python3 "$port/tools/audit-port.py" "$top" "$parent" "$art/source-before.json"
python3 - "$top" "$proposal" "$art" <<'PY'
from pathlib import Path
import hashlib,json,subprocess,sys
T,P,A=map(Path,sys.argv[1:]);r=json.loads((P/'staging-lock.json').read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for project in r['projects']:
 root=T/project['path'];assert subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()==project['revision']
 patch=P/project['patch'];assert sha(patch)==project['patch_sha256']
 for row in project['files']:
  path=root/row['path'];assert path.resolve().is_relative_to(root.resolve())
  if row['before_sha256'] is None:assert not path.exists()
  else:assert sha(path)==row['before_sha256'],path
 subprocess.run(['git','-C',str(root),'apply','--check',str(patch)],check=True)
expected={'Image':'33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553','dtbo.img':'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b','vendor.img':'a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a'}
for name,digest in expected.items():assert sha(T/'device/samsung/gta3xlwifi/prebuilt'/name)==digest
(A/'binary-inputs.json').write_text(json.dumps(expected,indent=2)+'\n')
print('All three project revisions and incremental patch/input hashes validated before mutation')
PY
git -C "$top/device/samsung/gta3xlwifi" fetch --no-tags https://github.com/oddhap/android_device_samsung_gta3xlwifi.git lineage-24.0-arm64
[[ $(git -C "$top/device/samsung/gta3xlwifi" rev-parse FETCH_HEAD) == e9984355a95f21e7fc2168b9dbf49d822406c513 ]]
git -C "$top/device/samsung/gta3xlwifi" merge --ff-only e9984355a95f21e7fc2168b9dbf49d822406c513
python3 - "$top" "$proposal" <<'PY'
from pathlib import Path
import hashlib,json,subprocess,sys
T,P=map(Path,sys.argv[1:]);r=json.loads((P/'staging-lock.json').read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for project in r['projects']:
 root=T/project['path']
 if project['path']!='device/samsung/gta3xlwifi':
  subprocess.run(['git','-C',str(root),'apply',str(P/project['patch'])],check=True)
  added=[row['path'] for row in project['files'] if row['before_sha256'] is None]
  if added:subprocess.run(['git','-C',str(root),'add','-N','--',*added],check=True)
 for row in project['files']:assert sha(root/row['path'])==row['candidate_sha256'],row['path']
print('Reviewed source proposal applied; all candidate hashes match')
PY
mapfile -t projects < <(python3 - "$parent/source-lock.json" <<'PY'
import json,sys
for row in json.load(open(sys.argv[1])):print(row['project'])
PY
)
cd "$top"
export PATH=/srv/android/bin:$PATH
python3 "$port/tools/capture-port.py" "$top" "$next" "${projects[@]}"
python3 "$port/tools/audit-port.py" "$top" "$next" "$next/port-audit.json"
python3 - "$parent" "$next" "$art" <<'PY'
from pathlib import Path
import hashlib,json,sys,xml.etree.ElementTree as ET
before,after,out=map(Path,sys.argv[1:]);old={x['project']:x for x in json.loads((before/'source-lock.json').read_text())};new={x['project']:x for x in json.loads((after/'source-lock.json').read_text())}
assert old.keys()==new.keys() and len(new)==15
changed=[p for p in old if old[p]!=new[p]];assert set(changed)=={'system/core','system/vold'},changed
manifest=lambda p:{x.get('path',x.get('name')):x.get('revision') for x in ET.parse(p/'port-manifest.xml').getroot().iter('project')}
a,b=manifest(before),manifest(after);assert a.keys()==b.keys() and len(a)==1243
revisions={p:[a[p],b[p]] for p in a if a[p]!=b[p]};assert revisions=={'device/samsung/gta3xlwifi':['2f649d06fec3318926c61aaf7a5fa3f40aa9f266','e9984355a95f21e7fc2168b9dbf49d822406c513']},revisions
report={'passed':True,'snapshot':str(after),'projects':len(a),'exact_source_patches':len(new),'changed_patch_projects':changed,'revision_changes':revisions,'prebuilts_promoted':False,'hardware_tested':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
PY
echo 'New locked fscrypt source snapshot captured/audited; no image or device modification.'
