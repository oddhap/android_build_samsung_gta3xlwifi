#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 53: snapshot52 + SD-card storage (issue #4): ro.crypto.volume.options=aes-256-xts:aes-256-cts:v1
# (F2FS on kernel 4.4 rejects the pre-Q AES-256-HEH default with EINVAL), persist.sys.adoptable=force_on
# (owner choice; the SD line is in the pinned vendor fstab), and the sdfat-exfat kernel (sdfat also
# registers as "exfat" so vold mounts exFAT cards) with the OTA kernel guard moved to it.
# Select kernel, stage, rebind the touch proof, full build, package checks, test OTA. Release signing
# is NOT part of this chain (separate owner go-ahead). Every step stops the chain.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
T=/srv/android/src/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime52-ota-checks-20261123-01.exit") == 0 ]]
[[ $(cat "$L/release-20261123-02-orchestrator.exit") == 0 ]]
[[ $(cat "$L/kernel-sdfat-exfat-build-20261123-01.exit") == 0 ]]
test -f "$A/runtime52-ota-build-20261123-01/target-files.zip"
python3 "$P/tools/audit-port.py" "$T" "$P/snapshots/port-20261123-52" "$A/runtime53-orchestrator-source-before.json"
python3 "$P/tools/select-runtime53-inputs24.py"
flock -n "$L/build.lock" bash -c 'set -e; source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1"' bash "$P/tools/stage-runtime53-source24.py"
flock -n "$L/build.lock" python3 "$P/tools/rebind-runtime53-touch-kernel24.py" runtime53-touch-kernel-rebind-20261123-01
bash "$P/tools/build-runtime53-product24.sh" runtime53-product-build-20261123-01 "$A/runtime53-inputs-20261123-02/report.json"
bash "$P/tools/run-runtime53-package24.sh"
[[ $(cat "$L/runtime53-package-workflow-20261123-01.exit") == 0 ]]
[[ $(cat "$L/runtime53-ota-checks-20261123-01.exit") == 0 ]]
