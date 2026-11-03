#!/usr/bin/env bash
# Read-only source fixtures after the standalone build releases its mutex.
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64/kernel-netlink-snapshot-build-20261103-01
label=kernel-netlink-snapshot-host-20261103-01
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; exit "$result"' EXIT
exec 9>"$logs/build.lock"
flock 9
test "$(cat "$logs/kernel-netlink-snapshot-build-20261103-01.exit")" = 0
python3 "$ports/lineage-24.0/tools/test-netlink-xperm24.py" \
 --kernel "$ports/kernel-netlink-snapshot-20261103-01/src" \
 --reference "$ports/kernel-xperm-generation-host-20261103-01/modern" \
 --legacy "$ports/kernel-xperm-generation-host-20261103-01/legacy" \
 --generation-bound --snapshot-bound --report "$art/host-avc-linux.json"
python3 "$ports/lineage-24.0/tools/test-kernel-netlink-snapshot.py" \
 --kernel "$ports/kernel-netlink-snapshot-20261103-01/src" \
 --before "$ports/kernel-xperm-generation-20261103-01/src" \
 --constants /srv/android/artifacts/lineage-24.0-arm64/kernel-netlink-constants-20261103-02/constants.json \
 --report "$art/host-hook-linux.json"
