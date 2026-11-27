#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 54: snapshot54-sync (snapshot53 patches on lineage-24.0 synced 2026-11-27) plus the
# Gta3xlwifiStatsJournal boot_id descriptor close (system_server fd leak -> EMFILE -> restart
# after ~3.7 days on build 53). Stage, full build, package checks, test OTA. Release signing
# is NOT part of this chain (separate owner go-ahead). Every step stops the chain.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
T=/srv/android/src/lineage-24.0-arm64
label=${1:?Fresh label required}
checkout=${CHECKOUT_LABEL:?CHECKOUT_LABEL required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/$checkout.exit") == 0 ]]
[[ $(cat "$L/runtime53-ota-checks-20261123-01.exit") == 0 ]]
test -f "$A/runtime53-ota-build-20261123-01/target-files.zip"
journal=$P/tools/runtime54-stats/Gta3xlwifiStatsJournal.java
[[ $(sha256sum "$journal" | cut -d' ' -f1) == d819492d68ab2d922a3caaf1e964ca0a9f8ecafc9eefa9bffb6f3d9f50f9b58d ]]
# capture-port.py needs repo on PATH (attempt -01 failed with FileNotFoundError: repo before any
# snapshot was kept; preserved as runtime54-source-selection-20261127-01-failed-a).
flock -n "$L/build.lock" bash -c 'set -e; source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1" "$2"' bash "$P/tools/stage-runtime54-source24.py" "$journal"
bash "$P/tools/build-runtime54-product24.sh" runtime54-product-build-20261127-01 "$A/runtime54-inputs-20261127-01/report.json"
bash "$P/tools/run-runtime54-package24.sh"
[[ $(cat "$L/runtime54-package-workflow-20261127-01.exit") == 0 ]]
[[ $(cat "$L/runtime54-ota-checks-20261127-01.exit") == 0 ]]
