#!/usr/bin/env bash
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64/kernel-capabilities-build-20261104-01
label=kernel-capabilities-host-20261104-01
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; exit "$result"' EXIT
exec 9>"$logs/build.lock"
flock 9
test "$(cat "$logs/kernel-capabilities-build-20261104-01.exit")" = 0
python3 "$ports/lineage-24.0/tools/collect-kernel-netlink-constants.py" \
 --src "$ports/kernel-capabilities-20261104-01/src" --out "$ports/kernel-capabilities-20261104-01/out" --report-dir "$art/constants"
python3 "$ports/lineage-24.0/tools/test-netlink-policy.py" \
 --kernel "$ports/kernel-capabilities-20261104-01/src" --kernel-out "$ports/kernel-capabilities-20261104-01/out" \
 --android-top /srv/android/src/lineage-24.0-arm64 \
 --policy /srv/android/artifacts/lineage-24.0-arm64/policy-binary-20261104-01/policy/init-runtime-diagnostic.policy \
 --constants "$art/constants/constants.json" --output "$art/netlink-policy"
python3 "$ports/lineage-24.0/tools/audit-kernel-tree.py" "$ports/kernel-capabilities-20261104-01/src" "$art/source-after-host.json"
python3 - "$art" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);a=json.loads((p/'source-after.json').read_text());b=json.loads((p/'source-after-host.json').read_text())
for k in ['revision','tree','tracked_sha256','diff_sha256']:assert a[k]==b[k],k
print('PASS: complete kernel source unchanged after real-policy host checks')
PY
