#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
P=/srv/android/ports/lineage-24.0-arm64/lineage-24.0
T=/srv/android/src/lineage-24.0-arm64
A=/srv/android/artifacts/lineage-24.0-arm64
L=/srv/android/logs/lineage-24.0-arm64
label=${1:?Fresh label required}
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$L/build.lock"; flock -n 9 || exit 75
[[ $(cat "$L/runtime17-product-build-20261117-01.exit") == 0 ]] || exit 1
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
archive=$T/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
python3 "$P/tools/check-runtime-target-files24.py" --top "$T" --archive "$archive" --snapshot "$P/snapshots/port-20261117-17" --source-audit "$A/runtime17-product-build-20261117-01/source-after.json" --build-exit "$L/runtime17-product-build-20261117-01.exit" --input-selection "$A/runtime17-inputs-20261117-01/report.json" --strict-report "$A/ion-policy-strict-20261117-02/strict/report.json" --vendor-report "$A/ion-vendor-composition-20261117-01/report.json" --report "$O/geometry-policy.json"
python3 "$P/tools/test-installer-hooks24.py" --top "$T" --archive "$archive" --source "$T/device/samsung/gta3xlwifi/releasetools.py" --output "$O/hooks"
python3 "$P/tools/check-runtime-ext4-features24.py" --top "$T" --archive "$archive" --geometry-report "$O/geometry-policy.json" --kernel /srv/android/ports/lineage-24.0-arm64/kernel-uid-receipt-20261115-01/src --output "$O/ext4"

python3 "$P/tools/check-firststage-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/firststage.json"

python3 "$P/tools/check-acct-root-target24.py" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/cpuacct-root.json"

python3 "$P/tools/check-vold-metadata-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/metadata-null-host-20261116-01/report.json" --reference "$A/runtime06-ota-build-20261116-01/target-files.zip" --output "$O/vold-metadata.json"

python3 "$P/tools/check-bpf-kernel-actual-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/bpf-kernel-actual-host-20261116-01/report.json" --output "$O/bpf-version.json"

python3 "$P/tools/check-netd-oneshot-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/netd-oneshot-global-host-20261116-02/report.json" --reference "$A/runtime09-ota-build-20261116-01/target-files.zip" --output "$O/netd-oneshot.json"

python3 "$P/tools/check-netd-first-guards-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/netd-first-guards-host-20261116-01/report.json" --reference "$A/runtime10-ota-build-20261116-01/target-files.zip" --output "$O/netd-first-guards.json"

python3 "$P/tools/check-legacy-gralloc-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/legacy-gralloc-host-20261117-02/report.json" --reference "$A/runtime11-ota-build-20261116-01/target-files.zip" --output "$O/legacy-gralloc.json"

python3 "$P/tools/check-ion-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/ion.json"

python3 "$P/tools/check-early-adb-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/early-adb.json"
