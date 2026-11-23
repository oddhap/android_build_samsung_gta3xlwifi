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
[[ $(cat "$L/runtime51-product-build-20261123-01.exit") == 0 ]] || exit 1
O=$A/$label
[[ ! -e $O && ! -e $L/$label.exit ]] || exit 2
mkdir "$O"
exec >"$L/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" >"$L/$label.exit"; exit "$rc"' EXIT
archive=$T/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
python3 "$P/tools/check-runtime51-target-files24.py" --boot-security-patch 2026-11-01 --top "$T" --archive "$archive" --snapshot "$P/snapshots/port-20261123-51" --source-audit "$A/runtime51-product-build-20261123-01/source-after.json" --build-exit "$L/runtime51-product-build-20261123-01.exit" --input-selection "$A/runtime51-inputs-20261123-01/report.json" --strict-report "$A/updion-policy-strict-20261122-01/strict/report.json" --vendor-report "$A/updion-vendor-20261122-01/report.json" --report "$O/geometry-policy.json"
python3 "$P/tools/check-runtime40-policy-contexts.py" --top "$T" --out-dir out --vendor "$A/updion-policy-strict-20261122-01/metadata/vendor" --policy "$A/updion-policy-strict-20261122-01/strict/strict.policy" --strict-report "$A/updion-policy-strict-20261122-01/strict/report.json" --output "$O/contexts"
python3 "$P/tools/test-installer-hooks24.py" --top "$T" --archive "$archive" --source "$T/device/samsung/gta3xlwifi/releasetools.py" --output "$O/hooks"
python3 "$P/tools/check-runtime40-ext4-features24.py" --top "$T" --archive "$archive" --geometry-report "$O/geometry-policy.json" --kernel /srv/android/ports/lineage-24.0-arm64/kernel-gate-split-20261121-02/src --output "$O/ext4"

python3 "$P/tools/check-runtime40-firststage-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/firststage.json"

python3 "$P/tools/check-acct-root-target24.py" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/cpuacct-root.json"

python3 "$P/tools/check-runtime40-vold-metadata-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/metadata-null-host-20261116-01/report.json" --reference "$A/runtime06-ota-build-20261116-01/target-files.zip" --output "$O/vold-metadata.json"

python3 "$P/tools/check-bpf-kernel-actual-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/runtime44-devicemk-rebind-20261121-01/bpf-kernel-actual-host-report.json" --output "$O/bpf-version.json"

python3 "$P/tools/check-netd-oneshot-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/netd-oneshot-global-host-20261116-02/report.json" --reference "$A/runtime09-ota-build-20261116-01/target-files.zip" --output "$O/netd-oneshot.json"

python3 "$P/tools/check-netd-first-guards-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/runtime42-netd-guards-rebind-20261121-01/netd-first-guards-host.json" --reference "$A/runtime10-ota-build-20261116-01/target-files.zip" --output "$O/netd-first-guards.json"

python3 "$P/tools/check-legacy-gralloc-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --host-proof "$A/runtime40-boardconfig-rebind-20261121-01/mapper-regression-binding.json" --reference "$A/runtime11-ota-build-20261116-01/target-files.zip" --output "$O/legacy-gralloc.json"

python3 "$P/tools/check-runtime46-ion-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/ion.json"

python3 "$P/tools/check-runtime40-early-adb-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/early-adb.json"

python3 "$P/tools/check-runtime46-aconfig24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/aconfig-cache.json"

python3 "$P/tools/check-runtime40-clat-bootstrap-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/clat-bootstrap.json"

python3 "$P/tools/check-local-note-listener-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --output "$O/local-note-listener.json"

python3 "$P/tools/check-lmkd-inkernel-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$O/lmkd.json"

python3 "$P/tools/check-runtime27-ui-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$A/runtime44-devicemk-rebind-20261121-01/ui-host-proof.json" "$O/ui.json"

python3 "$P/tools/check-runtime28-touch-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$A/runtime51-touch-rebind-20261123-01/touch-host-proof.json" "$O/touch-wake.json"

python3 "$P/tools/check-runtime36-netaccess-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$O/network-access-wait.json"

python3 "$P/tools/check-runtime37-lognoise-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$O/log-noise.json"

python3 "$P/tools/check-runtime46-bootspl-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$A/runtime51-product-build-20261123-01/build-vars.json" "$O/boot-security-patch.json"

python3 "$P/tools/check-runtime44-recovery-identity-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$O/recovery-identity.json"

python3 "$P/tools/check-runtime40-product-layout-target24.py" --top "$T" --archive "$archive" --geometry "$O/geometry-policy.json" --gapps "$A/gapps-mtg17-20261022/MindTheGapps-17.0.0-arm64-20261022_132445.zip" --gapps-sha256 a6844eeb2613541558237e467b20feb01f8b45b2ebab0109834140ea59b6ca4d --output "$O/product-layout.json"

python3 "$P/tools/check-runtime46-updater-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$O/updater.json"

python3 "$P/tools/check-runtime48-hwui-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$A/runtime48-source-selection-20261122-01/edits.json" "$A/runtime47-ota-build-20261122-01/target-files.zip" "$O/hwui.json"

python3 "$P/tools/check-runtime49-changelog-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$A/runtime49-source-selection-20261122-01/edits.json" "$O/changelog-url.json"

python3 "$P/tools/check-runtime50-uffd-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$A/runtime50-source-selection-20261122-01/edits.json" "$O/uffd-gc.json"

python3 "$P/tools/check-runtime51-power-target24.py" "$T" "$archive" "$O/geometry-policy.json" "$A/runtime51-source-selection-20261123-01/edits.json" "$A/runtime51-product-build-20261123-01/host-tests.json" "$O/power.json"
