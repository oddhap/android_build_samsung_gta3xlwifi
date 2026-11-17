#!/usr/bin/env bash
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
python3 "$P/tools/compose-local-note-listener-source24.py" --top "$T" --ports /srv/android/ports/lineage-24.0-arm64 --composition "$A/local-note-listener-source-composition-20261117-01" --parent "$P/snapshots/port-20261117-21" --snapshot "$P/snapshots/port-20261117-22" --output "$A/local-note-listener-source-selection-20261117-01"
python3 "$P/tools/inherit-runtime22-inputs24.py" "$A/runtime22-inputs-20261117-01"
bash "$P/tools/build-runtime22-product24.sh" runtime22-product-build-20261117-01 "$A/runtime22-inputs-20261117-01/report.json"
bash "$P/tools/run-runtime22-package24.sh"
