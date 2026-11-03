#!/usr/bin/env bash
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64/kernel-extsock-build-20261103-01
label=kernel-extsock-host-20261103-01
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; exit "$result"' EXIT
exec 9>"$logs/build.lock"
flock 9
test "$(cat "$logs/kernel-extsock-build-20261103-01.exit")" = 0
python3 "$ports/lineage-24.0/tools/test-kernel-extsock.py" \
 --kernel "$ports/kernel-extsock-20261103-01/src" \
 --before "$ports/kernel-netlink-snapshot-20261103-01/src" \
 --modern "$ports/kernel-mmap-host-inputs-20261103-01/modern" \
 --constants /srv/android/artifacts/lineage-24.0-arm64/kernel-socket-constants-20261103-03/constants.json \
 --report "$art/host-extsock-linux.json"
