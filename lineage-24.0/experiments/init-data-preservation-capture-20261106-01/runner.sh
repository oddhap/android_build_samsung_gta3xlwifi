#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
source /srv/android/ports/lineage-24.0-arm64/env.sh
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=init-data-preservation-capture-20261106-01
art=/srv/android/artifacts/lineage-24.0-arm64/$label
parent="$port/snapshots/port-20261106-01"
next="$port/snapshots/port-20261106-02"
proposal="$port/experiments/init-data-preservation-20261106-01"
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
[[ ! -e $art && ! -e $next && ! -e $logs/$label.exit ]]
exec >"$logs/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
mkdir "$art"; cp "$proposal/apply-capture.sh" "$art/runner.sh"
[[ $(cat "$logs/legacy-fscrypt-native-20261106-01.exit") == 0 ]]
python3 "$port/tools/audit-port.py" "$top" "$parent" "$art/source-before.json"
python3 - "$top" "$parent" "$proposal" "$art" <<'PY'
import hashlib,json,os,subprocess,sys
from pathlib import Path
T,B,P,A=map(Path,sys.argv[1:]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
lock=json.loads((P/'source-lock.json').read_text());file=T/lock['path'];assert sha(file)==lock['before_sha256'];patch=P/'system_core.patch';assert sha(patch)==lock['patch_sha256']
root=T/'system/core'
subprocess.run(['git','-C',str(root),'apply','--check',str(patch)],check=True)
subprocess.run(['git','-C',str(root),'apply',str(patch)],check=True)
assert sha(file)==lock['candidate_sha256']
index=A/'private-index';env=os.environ.copy();env['GIT_INDEX_FILE']=str(index)
def run(*args):subprocess.run(['git','-C',str(root),*args],env=env,check=True)
run('read-tree','HEAD');run('add','-u');run('apply','--cached','--reverse',str(patch))
diff=subprocess.check_output(['git','-C',str(root),'diff','--cached','--binary','--no-ext-diff','--full-index','HEAD'],env=env)
row=next(x for x in json.loads((B/'source-lock.json').read_text()) if x['project']=='system/core');assert sha(B/'patches'/row['patch'])==row['sha256'];assert diff==(B/'patches'/row['patch']).read_bytes();index.unlink()
(A/'composition-proof.json').write_text(json.dumps({'passed':True,'project':'system/core','parent_patch_sha256':row['sha256'],'incremental_patch_sha256':lock['patch_sha256'],'exact_parent_bytes_recovered':True,'source_or_real_index_modified_by_proof':False},indent=2)+'\n')
PY
mapfile -t projects < <(python3 - "$parent/source-lock.json" <<'PY'
import json,sys
for row in json.load(open(sys.argv[1])):print(row['project'])
PY
)
python3 "$port/tools/capture-port.py" --parent-snapshot "$parent" "$top" "$next" "${projects[@]}"
python3 "$port/tools/audit-port.py" "$top" "$next" "$next/port-audit.json"
python3 - "$parent" "$next" "$art" <<'PY'
import json,sys,xml.etree.ElementTree as ET
from pathlib import Path
B,N,A=map(Path,sys.argv[1:]);rows=lambda p:{x['project']:x for x in json.loads((p/'source-lock.json').read_text())};a,b=rows(B),rows(N)
assert a.keys()==b.keys() and len(b)==16
changed=[x for x in a if a[x]!=b[x]];assert changed==['system/core'],changed
manifest=lambda p:{x.get('path',x.get('name')):x.get('revision') for x in ET.parse(p/'port-manifest.xml').getroot().iter('project')}
assert manifest(B)==manifest(N) and len(manifest(N))==1243
(A/'report.json').write_text(json.dumps({'passed':True,'snapshot':str(N),'projects':1243,'exact_source_patches':16,'changed_patch_projects':changed,'revision_changes':{},'prebuilts_promoted':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n')
PY
