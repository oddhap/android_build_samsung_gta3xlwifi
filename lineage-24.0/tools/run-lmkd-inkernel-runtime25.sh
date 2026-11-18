#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
T=/srv/android/src/lineage-24.0-arm64
R=/srv/android/ports/lineage-24.0-arm64
P=$R/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
C=$A/lmkd-inkernel-composition-20261118-01
N=$P/snapshots/port-20261118-25
D=$A/lmkd-inkernel-source-selection-20261118-01
rel=system/memory/lmkd/lmkd.cpp
[[ $(cat "$L/runtime24-package-workflow-20261118-01.exit") == 0 ]]
flock -n "$L/build.lock" true
python3 "$P/tools/stage-lmkd-inkernel-boot24.py" "$T/$rel" "$C"
mkdir -p "$C/baseline/${rel%/*}" "$C/files/${rel%/*}"
cp "$T/$rel" "$C/baseline/$rel"
cp "$C/lmkd.cpp" "$C/files/$rel"
python3 "$P/tools/test-lmkd-inkernel-boot24.py" "$C/baseline/$rel" "$C/files/$rel" | tee "$C/host.log"
python3 - "$C" "$rel" <<'PY'
import hashlib,json,sys
from pathlib import Path
c=Path(sys.argv[1])
rel=sys.argv[2]
record=json.loads((c/'selection.json').read_text())
before=hashlib.sha256((c/'baseline'/rel).read_bytes()).hexdigest()
after=hashlib.sha256((c/'files'/rel).read_bytes()).hexdigest()
assert before==record['before_sha256'] and after==record['after_sha256']
(c/'selection.json').write_text(json.dumps({'files':{rel:{'before':before,'after':after}}})+'\n')
(c/'host-report.json').write_text(json.dumps({'passed':True,'source_sha256':{rel:after}})+'\n')
PY
python3 "$P/tools/compose-lmkd-inkernel-source24.py" --top "$T" --ports "$R" --composition "$C" --parent "$P/snapshots/port-20261118-24" --snapshot "$N" --output "$D"
python3 - "$A" "$N" "$D" <<'PY'
import hashlib,json,sys
from pathlib import Path
a,n,d=map(Path,sys.argv[1:])
p=a/'runtime24-inputs-20261118-01/report.json'
r=json.loads(p.read_text())
assert r['passed'] and json.loads((d/'report.json').read_text())['passed']
r.update(source_snapshot=str(n),inherited_runtime_selection_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),runtime_prebuilts_changed=False)
r['proofs_sha256'].update(json.loads((d/'selection.json').read_text())['proof_reports_sha256'])
o=a/'runtime25-inputs-20261118-01'
o.mkdir()
(o/'report.json').write_text(json.dumps(r,indent=2)+'\n')
PY
bash "$P/tools/build-runtime25-product24.sh" runtime25-product-build-20261118-01 "$A/runtime25-inputs-20261118-01/report.json"
bash "$P/tools/run-runtime25-package24.sh"
