#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Continue after production policy: strict report, then full diagnostic target-files.
# No OTA generation, release signing, installation or device access.
set -euo pipefail
port=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64
top=/srv/android/src/lineage-24.0-arm64
policy=policy-user-20261101-01
label=full-targetfiles-20261101-01
exec 8>"$logs/continue-diagnostic-build.lock"
flock -n 8 || { echo 'Continuation already active'; exit 1; }
[[ ! -e $logs/$label.log && ! -e $logs/$label.exit && ! -e $art/$label ]] || exit 1
pid=$(cat "$logs/$policy.pid")
[[ $pid =~ ^[0-9]+$ ]] || exit 1
while [[ ! -f $logs/$policy.exit ]]; do
    kill -0 "$pid" || { echo 'Policy runner stopped without an exit result'; exit 1; }
    sleep 15
done
[[ $(cat "$logs/$policy.exit") == 0 ]] || { echo 'Policy build failed; stopping continuation'; exit 1; }
[[ -f $art/$policy/source-audit-after.json ]] || exit 1
flock -n "$logs/build.lock" true || { echo 'Unexpected active build; stopping continuation'; exit 1; }
available=$(df --output=avail -B1 "$top" | tail -1)
(( available > 200 * 1024 * 1024 * 1024 )) || { echo 'Less than 200 GiB free; not starting full build'; exit 1; }
printf '[%s] Strict actual-vendor check of built production policy\n' "$(date -u +%FT%TZ)"
set +e
python3 "$port/lineage-24.0/tools/check-vendor-policy.py" --top "$top" \
    --out-dir "out-$policy" --vendor "$art/vendor-check-20261101-01/vendor" \
    --output "$art/vendor-policy-user-20261101-01"
rc=$?
set -e
[[ $rc == 0 || $rc == 1 ]] || exit "$rc"
# Require a real report: a tool error is not an expected strict policy failure.
python3 - "$art/vendor-policy-user-20261101-01/report.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['results'][0]['neverallow_checks_enabled']
assert r['build_output_root'].endswith('/out-policy-user-20261101-01')
print('Strict policy result:',r['passed_strict'])
print('Full build is diagnostic; it does not waive this result or approve installation.')
PY
printf '%s\n' 'Diagnostic target-files only. Strict vendor policy, kernel/network/runtime and installer gates remain.' > "$logs/$label.NOT_READY_FOR_FLASHING.txt"
ln -sfn "$label.log" "$logs/build-latest.log"
printf '%s\n' "$$" > "$logs/$label.pid"
bash "$port/lineage-24.0/tools/build-bringup.sh" "$label" target-files-package otatools > "$logs/$label.log" 2>&1
