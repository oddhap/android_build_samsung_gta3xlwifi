#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Complete-source audits around actual strict-policy host regressions.
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
top=/srv/android/src/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
label=${1:?Usage: check-strict-kernel-policy.sh NEW_LABEL KERNEL_BASE PRODUCTION_REPORT DEBUG_REPORT}
kernel=${2:?Missing isolated kernel base}
production=${3:?Missing production strict report}
debug=${4:?Missing userdebug strict report}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
[[ $kernel == /srv/android/ports/lineage-24.0-arm64/kernel-* && -d $kernel/src && -d $kernel/out ]] || exit 2
for report in "$production" "$debug"; do [[ $report == "$artifacts/"*/strict/report.json && -f $report ]] || exit 2; done
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
out="$artifacts/$label"; [[ ! -e $out && ! -e $logs/$label.exit ]] || exit 1
mkdir "$out"
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
cp "$port/tools/test-netlink-policy.py" "$out/runner.py"
cp "$port/tools/check-strict-kernel-policy.sh" "$out/runner.sh"
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-before.json"
python3 "$port/tools/audit-kernel-tree.py" "$kernel/src" "$out/kernel-before.json"
for profile in production userdebug; do
 if [[ $profile == production ]]; then input=$production; else input=$debug; fi
 python3 "$port/tools/test-netlink-policy.py" --kernel "$kernel/src" --kernel-out "$kernel/out" \
  --android-top "$top" --policy "${input%/*}/strict.policy" --strict-report "$input" \
  --constants "$artifacts/netlink-policy-constants-20261104-01/constants.json" --output "$out/$profile"
done
python3 "$port/tools/audit-kernel-tree.py" "$kernel/src" "$out/kernel-after.json"
python3 - "$out" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);a=json.loads((p/'kernel-before.json').read_text());b=json.loads((p/'kernel-after.json').read_text())
for k in ['revision','tree','tracked_sha256','diff_sha256']:assert a[k]==b[k],k
PY
python3 "$port/tools/audit-port.py" "$top" "$port/snapshots/port-20261103-07" "$out/source-after.json"
