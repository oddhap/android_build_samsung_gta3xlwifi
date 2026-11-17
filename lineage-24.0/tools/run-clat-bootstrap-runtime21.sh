#!/usr/bin/env bash
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
python3 "$P/tools/compose-clat-bootstrap-source24.py" --top "$T" --ports /srv/android/ports/lineage-24.0-arm64 --composition "$A/clat-bootstrap-source-composition-20261117-01" --parent "$P/snapshots/port-20261117-20" --snapshot "$P/snapshots/port-20261117-21" --output "$A/clat-bootstrap-source-selection-20261117-01"
python3 "$P/tools/inherit-runtime21-inputs24.py" "$A/runtime21-inputs-20261117-01"
bash "$P/tools/build-runtime21-product24.sh" runtime21-product-build-20261117-01 "$A/runtime21-inputs-20261117-01/report.json"
bash "$P/tools/run-runtime21-package24.sh"
