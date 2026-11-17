#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Strict fresh-source/vendor policy link, with explicitly fixed vendor metadata.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?New label required}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$L/build.lock"; flock -n 9 || exit 75
[[ $(cat "$L/ion-policy-build-20261117-01.exit") == 0 ]] || exit 1
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
python3 "$P/lineage-24.0/tools/audit-port.py" "$T" "$P/lineage-24.0/snapshots/port-20261117-14" "$O/source-before.json"
python3 - "$A" "$O" <<'PY'
from pathlib import Path
import hashlib,json,shutil,sys
A,O=map(Path,sys.argv[1:]);parent=A/'platform-policy-port-20261105-03/metadata/vendor'
# Fixed reviewed choices, never chosen in response to compiler failures.
V=O/'metadata/vendor';shutil.copytree(parent,V)
f=A/'vendor-app-data-types-20261105-02/metadata/vendor_sepolicy.cil'
assert hashlib.sha256(f.read_bytes()).hexdigest()=='7455615956ed1d316bae5b609fa24e759036478117915f497674ab74e170e161'
shutil.copyfile(f,V/'etc/selinux/vendor_sepolicy.cil')
f=V/'etc/selinux/plat_pub_versioned.cil'
assert hashlib.sha256(f.read_bytes()).hexdigest()=='5478939b47a7980cd4abe373a0825d812c8f103f65d9d2dd8883781f39b20a6f'
(O/'vendor-input-choice.json').write_text(json.dumps({'selection':'Explicit Android 11 platform behavior replacement with Android 17, preserving legacy symbols and Samsung assertions.','files_sha256':{str(f.relative_to(V)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(V.rglob('*')) if f.is_file()},'source_platform_overrides':False,'image_selection_changed':False},indent=2)+'\n')
PY
python3 "$P/lineage-24.0/tools/check-vendor-policy.py" --top "$T" --vendor "$O/metadata/vendor" --out-dir out --output "$O/strict"
python3 "$P/lineage-24.0/tools/check-policy-contexts.py" --top "$T" --out-dir out --vendor "$O/metadata/vendor" --policy "$O/strict/strict.policy" --strict-report "$O/strict/report.json" --output "$O/contexts"
python3 "$P/lineage-24.0/tools/check-composed-policy-assertions24.py" --baseline "$A/ion-policy-baseline-20261117-01/report.json" --candidate "$O/strict/report.json" --output "$O/assertions.json"
python3 "$P/lineage-24.0/tools/audit-port.py" "$T" "$P/lineage-24.0/snapshots/port-20261117-14" "$O/source-after.json"
