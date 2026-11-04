#!/usr/bin/env bash
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64/kernel-notify-build-20261104-01
label=kernel-notify-host-20261104-01
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; exit "$result"' EXIT
exec 9>"$logs/build.lock"
flock 9
test "$(cat "$logs/kernel-notify-build-20261104-01.exit")" = 0
python3 "$ports/lineage-24.0/tools/test-kernel-notify.py" \
 --kernel "$ports/kernel-notify-20261104-01/src" \
 --before "$ports/kernel-prlimit-20261103-01/src" \
 --inotify-header "$ports/kernel-notify-20261104-01/src/include/linux/inotify.h" \
 --report "$art/host-notify-linux.json"
