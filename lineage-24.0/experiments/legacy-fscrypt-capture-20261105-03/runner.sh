#!/usr/bin/env bash
# Finish capture after frozen, unchanged source whitespace blocked the first attempt.
set -euo pipefail
source /srv/android/ports/lineage-24.0-arm64/env.sh
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=legacy-fscrypt-capture-20261105-03
art=/srv/android/artifacts/lineage-24.0-arm64/$label
parent="$port/snapshots/port-20261103-07"
next="$port/snapshots/port-20261105-02"
proposal="$port/experiments/legacy-fscrypt-20261105-02"
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
[[ ! -e $art && ! -e $next && ! -e $logs/$label.exit ]]
mkdir "$art"
cp "$proposal/finish-snapshot.sh" "$art/runner.sh"
cp "$port/tools/capture-port.py" "$art/capture-port.py"
python3 - "$top" "$proposal" "$parent" "$art" <<'PY'
from pathlib import Path
import hashlib,json,os,subprocess,sys
T,P,B,A=map(Path,sys.argv[1:]);proposal=json.loads((P/'staging-lock.json').read_text());parent=json.loads((B/'source-lock.json').read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
proposals={x['path']:x for x in proposal['projects']};report=[]
for project in proposals.values():
 for row in project['files']:assert sha(T/project['path']/row['path'])==row['candidate_sha256'],row['path']
assert subprocess.check_output(['git','-C',str(T/'device/samsung/gta3xlwifi'),'rev-parse','HEAD'],text=True).strip()=='e9984355a95f21e7fc2168b9dbf49d822406c513'
assert not subprocess.check_output(['git','-C',str(T/'device/samsung/gta3xlwifi'),'diff','HEAD'])
for row in parent:
 root=T/row['project'];base=B/'patches'/row['patch'];assert sha(base)==row['sha256']
 assert subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()==row['revision']
 spec=proposals.get(row['project']);env=os.environ.copy()
 if spec:
  patch=P/spec['patch'];assert sha(patch)==spec['patch_sha256']
  index=A/(row['project'].replace('/','_')+'.temporary-index');assert not index.exists();env['GIT_INDEX_FILE']=str(index)
  def run(*args):return subprocess.run(['git','-C',str(root),*args],env=env,check=True)
  run('read-tree','HEAD');run('add','-u')
  added=[x['path'] for x in spec['files'] if x['before_sha256'] is None]
  if added:run('add','--',*added)
  run('apply','--cached','--reverse','--check',str(patch));run('apply','--cached','--reverse',str(patch))
  diff=subprocess.check_output(['git','-C',str(root),'diff','--cached','--binary','--no-ext-diff','--full-index','HEAD'],env=env)
  index.unlink()
 else:diff=subprocess.check_output(['git','-C',str(root),'diff','--binary','--no-ext-diff','--full-index','HEAD'])
 assert diff==base.read_bytes(),row['project']
 report.append({'project':row['project'],'parent_patch_sha256':row['sha256'],'incremental_patch_reversed_in_private_index':bool(spec),'exact_parent_bytes_recovered':True})
(A/'composition-proof.json').write_text(json.dumps({'passed':True,'projects':report,'source_or_real_index_modified_by_proof':False},indent=2)+'\n')
print('PASS: all15 project deltas exactly equal reviewed parent plus locked fscrypt proposal')
PY
mapfile -t projects < <(python3 - "$parent/source-lock.json" <<'PY'
import json,sys
for row in json.load(open(sys.argv[1])):print(row['project'])
PY
)
cd "$top"
python3 "$port/tools/capture-port.py" --parent-snapshot "$parent" "$top" "$next" "${projects[@]}"
python3 "$port/tools/audit-port.py" "$top" "$next" "$next/port-audit.json"
python3 - "$parent" "$next" "$art" <<'PY'
from pathlib import Path
import json,sys,xml.etree.ElementTree as ET
before,after,out=map(Path,sys.argv[1:]);old={x['project']:x for x in json.loads((before/'source-lock.json').read_text())};new={x['project']:x for x in json.loads((after/'source-lock.json').read_text())}
assert old.keys()==new.keys() and len(new)==15
changed=[p for p in old if old[p]!=new[p]];assert set(changed)=={'system/core','system/vold'},changed
manifest=lambda p:{x.get('path',x.get('name')):x.get('revision') for x in ET.parse(p/'port-manifest.xml').getroot().iter('project')}
a,b=manifest(before),manifest(after);assert a.keys()==b.keys() and len(a)==1243
revisions={p:[a[p],b[p]] for p in a if a[p]!=b[p]};assert revisions=={'device/samsung/gta3xlwifi':['2f649d06fec3318926c61aaf7a5fa3f40aa9f266','e9984355a95f21e7fc2168b9dbf49d822406c513']},revisions
(out/'report.json').write_text(json.dumps({'passed':True,'snapshot':str(after),'projects':len(a),'exact_source_patches':len(new),'changed_patch_projects':changed,'revision_changes':revisions,'prebuilts_promoted':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n')
PY
echo 'Complete source snapshot audited; original binary inputs unchanged.'
