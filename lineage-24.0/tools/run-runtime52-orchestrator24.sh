#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 52: snapshot51 + stats rows whose ifindex has no interface name are skipped
# (logged once per read above 100 kB) as in A17 BpfNetworkStats.cpp instead of throwing
# "Missing real interface history: 0", which crash-looped system_server on Wi-Fi
# (issue #5). Stage, host test on the staged tree, rebind unchanged inputs, full build,
# package checks, test OTA, then owner-approved release signing (release-20261123-02).
# Every step stops the chain.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime51-ota-checks-20261123-01.exit") == 0 ]]
[[ $(cat "$L/release-20261123-01-orchestrator.exit") == 0 ]]
test -f "$A/runtime51-ota-build-20261123-01/target-files.zip"
flock -n "$L/build.lock" bash -c 'set -e; source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime52-source24.py"
S=/srv/android/src/lineage-24.0-arm64/packages/modules/Connectivity/service/src/com/android/server
W=$A/runtime52-source-selection-20261123-01/originals
python3 "$P/tools/test-runtime52-unknown-iface24.py" --top /srv/android/src/lineage-24.0-arm64 --consumer-before "$W/Gta3xlwifiStatsConsumer.java" --traffic-before "$W/Gta3xlwifiTrafficStats.java" --consumer-after "$S/Gta3xlwifiStatsConsumer.java" --traffic-after "$S/Gta3xlwifiTrafficStats.java" --output "$A/runtime52-unknown-iface-host-20261123-04"
python3 "$P/tools/select-runtime52-inputs24.py"
bash "$P/tools/build-runtime52-product24.sh" runtime52-product-build-20261123-01 "$A/runtime52-inputs-20261123-01/report.json"
bash "$P/tools/run-runtime52-package24.sh"
[[ $(cat "$L/runtime52-package-workflow-20261123-01.exit") == 0 ]]
[[ $(cat "$L/runtime52-ota-checks-20261123-01.exit") == 0 ]]
bash "$P/tools/run-release-ota24.sh" release-20261123-02 runtime52-ota-build-20261123-01
[[ $(cat "$L/release-20261123-02-orchestrator.exit") == 0 ]]
