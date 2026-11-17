#!/usr/bin/env bash
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
flock -n /srv/android/logs/lineage-24.0-arm64/build.lock python3 "$P/tools/stage-legacy-shm-source24.py"
python3 "$P/tools/compose-legacy-shm-source24.py" --top "$T" --ports /srv/android/ports/lineage-24.0-arm64 --composition "$A/legacy-shm-source-composition-20261117-01" --parent "$P/snapshots/port-20261117-17" --snapshot "$P/snapshots/port-20261117-18" --output "$A/legacy-shm-source-selection-20261117-01"
bash "$P/tools/build-legacy-shm-policy24.sh" legacy-shm-policy-build-20261117-01
bash "$P/tools/check-legacy-shm-policy24.sh" legacy-shm-policy-strict-20261117-01
