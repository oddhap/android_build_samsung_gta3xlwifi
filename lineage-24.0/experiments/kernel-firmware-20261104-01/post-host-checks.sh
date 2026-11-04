#!/usr/bin/env bash
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64/kernel-firmware-build-20261104-01
label=kernel-firmware-host-20261104-01
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; exit "$result"' EXIT
exec 9>"$logs/build.lock"
flock 9
test "$(cat "$logs/kernel-firmware-build-20261104-01.exit")" = 0
python3 "$ports/lineage-24.0/tools/test-kernel-firmware.py" \
 --kernel "$ports/kernel-firmware-20261104-01/src" \
 --before "$ports/kernel-perf-20261104-01/src" \
 --report "$art/host-firmware-linux.json"
