#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
source /srv/android/ports/lineage-24.0-arm64/env.sh
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=network-stats-access-capture-20261106-01
art=/srv/android/artifacts/lineage-24.0-arm64/$label
parent="$port/snapshots/port-20261106-03"
next="$port/snapshots/port-20261106-04"
proposal="$port/experiments/network-stats-access-20261106-01"
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
[[ ! -e $art && ! -e $next && ! -e $logs/$label.exit ]]
exec >"$logs/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
mkdir "$art"; cp "$proposal/integrate-capture.sh" "$art/runner.sh"
[[ $(cat "$logs/network-stats-access-20261106-02.exit") == 0 ]]
python3 "$port/tools/audit-port.py" "$top" "$parent" "$art/source-before.json"
python3 - "$top" "$port" "$proposal" "$parent" "$art" <<'PY'
from pathlib import Path
import hashlib,json,os,subprocess,sys
T,P,S,B,A=map(Path,sys.argv[1:]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();lock=json.loads((S/'source-lock.json').read_text());d=json.loads((S/'device-source-lock.json').read_text())
for path in [Path('/srv/android/artifacts/lineage-24.0-arm64/qtaguid-adapter-host-20261106-03/report.json'),Path('/srv/android/artifacts/lineage-24.0-arm64/qtaguid-access-contract-20261106-02/report.json')]:
 report=json.loads(path.read_text());assert report['passed']
 if 'passed_cases' in report:assert report['passed_cases']==37 and report['stderr']==''
for profile in ['production','debug']:
 report=json.loads(Path('/srv/android/artifacts/lineage-24.0-arm64/qtaguid-access-policy-'+profile+'-20261106-01/report.json').read_text());assert report['passed'] and report['no_permissive_domains']
root=T/lock['project'];device=T/'device/samsung/gta3xlwifi'
assert subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()==lock['revision']
for row in lock['files']:assert sha(root/row['path'])==row['before_sha256']
assert subprocess.check_output(['git','-C',str(device),'rev-parse','HEAD'],text=True).strip()==d['old_revision'];assert not subprocess.check_output(['git','-C',str(device),'status','--porcelain']);assert sha(device/d['changed_path'])==d['before_sha256']
# Fetch finishes before any source mutation. Only this reviewed descendant may move HEAD.
subprocess.run(['git','-C',str(device),'fetch','--no-tags','https://github.com/oddhap/android_device_samsung_gta3xlwifi.git','lineage-24.0-arm64'],check=True)
assert subprocess.check_output(['git','-C',str(device),'rev-parse','FETCH_HEAD'],text=True).strip()==d['new_revision']
subprocess.run(['git','-C',str(device),'merge-base','--is-ancestor',d['old_revision'],d['new_revision']],check=True)
assert subprocess.check_output(['git','-C',str(device),'diff','--name-only',d['old_revision'],d['new_revision']],text=True).splitlines()==[d['changed_path']]
subprocess.run(['git','-C',str(device),'merge','--ff-only',d['new_revision']],check=True);assert sha(device/d['changed_path'])==d['candidate_sha256'];assert not subprocess.check_output(['git','-C',str(device),'status','--porcelain'])
patch=S/'packages_modules_Connectivity.patch';assert sha(patch)==lock['patch_sha256'];subprocess.run(['git','-C',str(root),'apply','--check',str(patch)],check=True);subprocess.run(['git','-C',str(root),'apply',str(patch)],check=True)
for row in lock['files']:assert sha(root/row['path'])==row['candidate_sha256']
index=A/'private-index';env=os.environ.copy();env['GIT_INDEX_FILE']=str(index)
def run(*args):subprocess.run(['git','-C',str(root),*args],env=env,check=True)
run('read-tree','HEAD');run('add','-u')
original=json.loads((P/'experiments/network-stats-native-20261106-02/source-lock.json').read_text());added=[row['path'] for row in original['files'] if row['before_sha256'] is None]
if added:run('add','--',*added)
run('apply','--cached','--reverse',str(patch));diff=subprocess.check_output(['git','-C',str(root),'diff','--cached','--binary','--no-ext-diff','--full-index','HEAD'],env=env);index.unlink()
parent=next(row for row in json.loads((B/'source-lock.json').read_text()) if row['project']==lock['project']);assert sha(B/'patches'/parent['patch'])==parent['sha256'];assert diff==(B/'patches'/parent['patch']).read_bytes()
expected={'Image':'33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553','dtbo.img':'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b','vendor.img':'a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a'}
for name,h in expected.items():assert sha(device/'prebuilt'/name)==h
(A/'composition-proof.json').write_text(json.dumps({'passed':True,'project':lock['project'],'exact_parent_patch_recovered':True,'parent_patch_sha256':parent['sha256'],'incremental_patch_sha256':lock['patch_sha256'],'source_or_real_index_modified_by_proof':False,'device_revision_change':d,'original_binary_inputs':expected,'readiness_or_policy_image_changes':False},indent=2)+'\n')
PY
mapfile -t projects < <(python3 - "$parent/source-lock.json" <<'PY'
import json,sys
for row in json.load(open(sys.argv[1])):print(row['project'])
PY
)
python3 "$port/tools/capture-port.py" --parent-snapshot "$parent" "$top" "$next" "${projects[@]}"
python3 "$port/tools/audit-port.py" "$top" "$next" "$next/port-audit.json"
python3 - "$parent" "$next" "$art" "$proposal" <<'PY'
from pathlib import Path
import json,sys,xml.etree.ElementTree as ET
B,N,A,P=map(Path,sys.argv[1:]);rows=lambda p:{x['project']:x for x in json.loads((p/'source-lock.json').read_text())};a,b=rows(B),rows(N);assert len(a)==len(b)==17 and a.keys()==b.keys();assert [x for x in a if a[x]!=b[x]]==['packages/modules/Connectivity']
manifest=lambda p:{x.get('path',x.get('name')):x.get('revision') for x in ET.parse(p/'port-manifest.xml').getroot().iter('project')};a,b=manifest(B),manifest(N);assert a.keys()==b.keys() and len(b)==1243;changed={x:[a[x],b[x]] for x in a if a[x]!=b[x]};d=json.loads((P/'device-source-lock.json').read_text());assert changed=={'device/samsung/gta3xlwifi':[d['old_revision'],d['new_revision']]}
(A/'report.json').write_text(json.dumps({'passed':True,'snapshot':str(N),'projects':1243,'exact_source_patches':17,'changed_patch_project':'packages/modules/Connectivity','revision_changes':changed,'readiness_or_policy_image_changes':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n')
PY
