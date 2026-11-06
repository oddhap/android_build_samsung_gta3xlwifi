#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Integrate only reviewed real qtaguid accounting, never fake BPF readiness.
set -euo pipefail
source /srv/android/ports/lineage-24.0-arm64/env.sh
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=network-stats-capture-20261106-01
art=/srv/android/artifacts/lineage-24.0-arm64/$label
parent="$port/snapshots/port-20261106-02"
next="$port/snapshots/port-20261106-03"
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
[[ ! -e $art && ! -e $next && ! -e $logs/$label.exit ]]
exec >"$logs/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
mkdir "$art"; cp "$port/experiments/network-stats-native-20261106-02/integrate-capture.sh" "$art/runner.sh"
for job in network-stats-native-20261106-02 network-stats-java-20261106-01; do
 [[ $(cat "$logs/$job.exit") == 0 ]]
done
python3 "$port/tools/audit-port.py" "$top" "$parent" "$art/source-before.json"
python3 - "$top" "$port" "$art" <<'PY'
from pathlib import Path
import hashlib,json,os,subprocess,sys
T,P,A=map(Path,sys.argv[1:]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();root=T/'packages/modules/Connectivity'
assert subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()=='7c04d866538e6f689823b769fb5c1e614ca0e295'
assert not subprocess.check_output(['git','-C',str(root),'status','--porcelain'])
specs=[];all_files=set()
for name in ['network-stats-native-20261106-02','network-stats-java-20261106-01']:
 path=P/'experiments'/name;lock=json.loads((path/'source-lock.json').read_text());patch=path/'packages_modules_Connectivity.patch';assert sha(patch)==lock['patch_sha256'];assert lock['project']=='packages/modules/Connectivity'
 for row in lock['files']:
  assert row['path'] not in all_files;all_files.add(row['path']);file=root/row['path']
  if row['before_sha256'] is None:assert not file.exists()
  else:assert sha(file)==row['before_sha256']
 subprocess.run(['git','-C',str(root),'apply','--check',str(patch)],check=True)
 subprocess.run(['git','-C',str(root),'apply',str(patch)],check=True)
 for row in lock['files']:assert sha(root/row['path'])==row['candidate_sha256']
 specs.append((lock,patch))
# Verify the resulting source equals exactly these two reviewed deltas.
index=A/'private-index';env=os.environ.copy();env['GIT_INDEX_FILE']=str(index)
def run(*args):subprocess.run(['git','-C',str(root),*args],env=env,check=True)
run('read-tree','HEAD');run('add','-u')
added=[row['path'] for lock,patch in specs for row in lock['files'] if row['before_sha256'] is None]
if added:run('add','--',*added)
for lock,patch in reversed(specs):run('apply','--cached','--reverse',str(patch))
assert not subprocess.check_output(['git','-C',str(root),'diff','--cached','--binary','HEAD'],env=env);index.unlink()
# Explicit intent-to-add is necessary for Repo capture to include only these
# reviewed new files; no unrelated untracked input is accepted.
if added:subprocess.run(['git','-C',str(root),'add','-N','--',*added],check=True)
(A/'composition-proof.json').write_text(json.dumps({'passed':True,'project':'packages/modules/Connectivity','exact_clean_head_recovered':True,'source_or_real_index_modified_by_proof':False,'reviewed_files':sorted(all_files),'patches':[{'sha256':lock['patch_sha256'],'path':str(patch)} for lock,patch in specs],'network_readiness_or_loader_changes':False},indent=2)+'\n')
PY
mapfile -t projects < <(python3 - "$parent/source-lock.json" <<'PY'
import json,sys
for row in json.load(open(sys.argv[1])):print(row['project'])
print('packages/modules/Connectivity')
PY
)
python3 "$port/tools/capture-port.py" --parent-snapshot "$parent" "$top" "$next" "${projects[@]}"
python3 "$port/tools/audit-port.py" "$top" "$next" "$next/port-audit.json"
python3 - "$parent" "$next" "$art" <<'PY'
from pathlib import Path
import json,sys,xml.etree.ElementTree as ET
B,N,A=map(Path,sys.argv[1:]);rows=lambda p:{x['project']:x for x in json.loads((p/'source-lock.json').read_text())};a,b=rows(B),rows(N)
assert len(a)==16 and len(b)==17 and b.keys()-a.keys()=={'packages/modules/Connectivity'}
assert all(a[x]==b[x] for x in a)
manifest=lambda p:{x.get('path',x.get('name')):x.get('revision') for x in ET.parse(p/'port-manifest.xml').getroot().iter('project')}
assert manifest(B)==manifest(N) and len(manifest(N))==1243
(A/'report.json').write_text(json.dumps({'passed':True,'snapshot':str(N),'projects':1243,'exact_source_patches':17,'new_patch_project':'packages/modules/Connectivity','all_parent_patches_byte_identical':True,'revision_changes':{},'network_readiness_or_loader_changes':False,'prebuilts_promoted':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n')
PY
