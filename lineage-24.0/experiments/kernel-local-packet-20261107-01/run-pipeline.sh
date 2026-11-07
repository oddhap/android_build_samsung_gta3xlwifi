#!/usr/bin/env bash
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
integration=$ports/lineage-24.0
logs=/srv/android/logs/lineage-24.0-arm64
label=local-network-pipeline-20261107-01
exec >"$logs/$label.log" 2>&1
finish(){ result=$?; trap - EXIT; printf '%s\n' "$result" >"$logs/$label.exit"; date -u; exit "$result"; }
trap finish EXIT
# Each child acquires the shared lock. No outer lock or source mutation.
bash "$integration/experiments/kernel-local-packet-20261107-01/build-kernel.sh"
python3 "$integration/tools/compile-xtables-local-network24.py" --top /srv/android/src/lineage-24.0-arm64 --source "$ports/xtables-local-network24-20261107-01" --kernel "$ports/kernel-local-packet-20261107-01/src" --snapshot "$integration/snapshots/port-20261106-04" --output /srv/android/artifacts/lineage-24.0-arm64/xtables-local-network-native-20261107-01
bash "$ports/run-local-network-policy-20261107-01.sh"
