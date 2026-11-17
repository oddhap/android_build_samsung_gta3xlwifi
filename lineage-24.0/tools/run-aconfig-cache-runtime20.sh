#!/usr/bin/env bash
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
python3 "$P/tools/compose-aconfig-cache-source24.py" --top "$T" --ports /srv/android/ports/lineage-24.0-arm64 --composition "$A/aconfig-cache-source-composition-20261117-01" --parent "$P/snapshots/port-20261117-19" --snapshot "$P/snapshots/port-20261117-20" --output "$A/aconfig-cache-source-selection-20261117-01"
python3 "$P/tools/inherit-runtime20-inputs24.py" "$A/runtime20-inputs-20261117-01"
bash "$P/tools/build-runtime20-product24.sh" runtime20-product-build-20261117-01 "$A/runtime20-inputs-20261117-01/report.json"
bash "$P/tools/run-runtime20-package24.sh"
