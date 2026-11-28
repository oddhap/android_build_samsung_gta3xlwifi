#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build 55: snapshot54 plus the issue #6 e2fsck fix (external/e2fsprogs ignores the Samsung
# EXT4_POLICY_FLAGS_PRIVATE_ALGO bit in v1 policies with different modes, so a forced
# "e2fsck -f -y" after an unclean shutdown no longer clears every FBE file). Stage, full build,
# package checks, test OTA. Release signing is NOT part of this chain (separate owner go-ahead).
# Every step stops the chain.
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ ! -e $L/$label.exit ]] || exit 2
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$L/$label.exit"; exit "$rc"' EXIT
[[ $(cat "$L/runtime54-ota-checks-20261127-01.exit") == 0 ]]
test -f "$A/runtime54-ota-build-20261127-01/target-files.zip"
patch=$P/tools/runtime55-e2fsck/external_e2fsprogs.patch
[[ $(sha256sum "$patch" | cut -d' ' -f1) == f6d36fc92402c546ed019d61c3669b5917809059f427f8ac59e427721456720c ]]
# capture-port.py needs repo on PATH (env.sh).
flock -n "$L/build.lock" bash -c 'set -e; source /srv/android/ports/lineage-24.0-arm64/env.sh; python3 "$1" "$2"' bash "$P/tools/stage-runtime55-source24.py" "$patch"
cd /srv/android/src/lineage-24.0-arm64
bash "$P/tools/build-runtime55-product24.sh" runtime55-product-build-20261128-01 "$A/runtime55-inputs-20261128-01/report.json"
bash "$P/tools/run-runtime55-package24.sh"
[[ $(cat "$L/runtime55-package-workflow-20261128-01.exit") == 0 ]]
[[ $(cat "$L/runtime55-ota-checks-20261128-01.exit") == 0 ]]
