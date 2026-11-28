#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# LineageOS 21 (SM-T510): add the ABGR TWRP identity to the OTA recovery-header
# helper, build, release-sign with the existing LineageOS 21 keys and run the same
# checks as the 2026-11-27 release. Nothing is published here.
set -euo pipefail
job=/srv/android/ports/lineage21-twrp-20261128
art=/srv/android/artifacts/lineage21-twrp-20261128
logs=/srv/android/logs/lineage21-twrp-20261128
fix=/srv/android/ports/lineage21-fixes-20261127
port=/srv/android/ports/lineage-21-arm64
notes=$port/lineage-21
top=/srv/android/src/lineage-21.0-arm64
dev=$top/device/samsung/gta3xlwifi
base=/srv/android/artifacts/lineage-21-arm64
release=$base/release
gapps=/srv/android/artifacts/gapps-arm64/MindTheGapps-14.0.0-arm64-20250203_200051.zip
simg2img=$top/out/host/linux-x86/bin/simg2img
tf=$top/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
cpp=recovery-header-sync/recovery_header_sync.cpp
label=twrp21-build
exec >"$logs/$label.log" 2>&1
finish() { result=$?; trap - EXIT; printf '%s\n' "$result" >"$logs/$label.exit"; date -u; exit "$result"; }
trap finish EXIT
printf 'Started '; date -u
grep -qx "passed 14 cases" "$logs/header-sync-test.log"
test "$(cat /srv/android/logs/lineage-21-arm64/full-build.exit)" = 0
test ! -e "$art/device-before.tar" && test ! -e "$art/release-before"
# The device tree must be exactly the published 2026-11-27 source for this file.
test "$(sha256sum "$dev/$cpp" | cut -d' ' -f1)" = 563f59a2b1ed70e4a8b81db8ad2732958b493066678f12f329a29455ea41a157
(cd "$dev" && sha256sum -c "$fix/device-new.sha256" --quiet --strict)
tar -C "$dev" -cf "$art/device-before.tar" .
mkdir -p "$art/build-identity-before"
for f in build-number-arm64 build-datetime-arm64; do
  if [[ -f $port/lineage-21/$f ]]; then mv "$port/lineage-21/$f" "$art/build-identity-before/$f"; fi
done
cp "$job/recovery_header_sync.cpp" "$dev/$cpp"
test "$(sha256sum "$dev/$cpp" | cut -d' ' -f1)" = 007fbee32149c34a604a6327038487cdcdc2babe88da248eb663f3c220109eb4
echo 'Staged recovery header helper with the ABGR TWRP identity'
export LINEAGE_BUILD_JOBS=16
bash "$port/build-arm64-candidate.sh" >"$logs/stage-build.log" 2>&1
test "$(cat /srv/android/logs/lineage-21-arm64/full-build.exit)" = 0
cat "$port/lineage-21/build-number-arm64"
cp "$tf" "$art/unsigned-target-files.zip"
sha256sum "$art/unsigned-target-files.zip" >"$art/SHA256SUMS"
# The helper in the built system must carry all four identities.
unzip -p "$art/unsigned-target-files.zip" SYSTEM/bin/gta3xlwifi_recovery_header_sync >"$art/helper.bin"
for id in 0c641ba8f29bd9a4063cf9e8670dfc84124bc926f7bead643977685827306cc6 \
          d8878895ec55959e9f3697c1ee3e8a983e304067a2cde26baa51d00fe664b751 \
          5eb6d0f8fbb75f08d7156d3de1118fc429eff44543fd61e6a7c1b8c99dc21239 \
          45344fd27769764622738f99d938ff3cce0d186764c7c23ddc872de292468bf0; do
  grep -aq "$id" "$art/helper.bin"
done
echo 'helper identities: PASS'
python3 "$port/check-signing-inputs.py" /srv/android/signing/arm64-baseline-sha256.json
mv "$release" "$art/release-before"
python3 "$notes/tools/verify-gapps-headroom.py" --release "$art/pre-sign" --target-files "$tf" \
  --gapps "$gapps" --simg2img "$simg2img" \
  --baseline-target-files "$art/release-before/signed-target-files.zip" >"$logs/unsigned-gapps-headroom.log" 2>&1
echo 'unsigned-gapps-headroom: PASS'
python3 "$notes/tools/sign-release.py" "$tf" >"$logs/signing.log" 2>&1
echo 'signing: PASS'
mount=$base/vendor-hybrid-mount
mountpoint -q "$mount"
findmnt -no OPTIONS "$mount" | grep -q '^ro'
test "$(sha256sum "$mount/etc/init/init.exynos7904.usb.rc" | cut -d' ' -f1)" = 500d6fccbb990aad93a7de7fb4cf7e96d00702702bd021d18c9152d74e59ef1d
python3 "$notes/tools/check-stock-vendor-policy.py" --runtime-mode >"$logs/vendor-policy.log" 2>&1
echo 'vendor-policy: PASS'
python3 "$notes/tools/check-native-vintf.py" >"$logs/native-vintf.log" 2>&1
echo 'native-vintf: PASS'
bash "$notes/tools/validate-arm64-candidate.sh" >"$logs/offline-validation.log" 2>&1
cat "$logs/offline-validation.log"
python3 "$notes/tools/verify-gapps-headroom.py" --release "$release" --gapps "$gapps" --simg2img "$simg2img" \
  --baseline-target-files "$art/release-before/signed-target-files.zip" >"$logs/gapps-headroom.log" 2>&1
echo 'gapps-headroom: PASS'
ota=$(ls "$release"/lineage-21.0-*-UNOFFICIAL-gta3xlwifi-arm64-privatekeys.zip)
test "$(printf '%s\n' "$ota" | wc -l)" = 1
python3 "$fix/check-fixes21.py" "$release/signed-target-files.zip" --ota "$ota" \
  --kernel-sha256 c7b4a44fcb4f31ea53d86fe000270d6a20d0f9d3e5a84ae9249c9d0acba19aca \
  --vendor-sha256 80aaf6c792e6ab97132f05301db3882316325f54a7776fff4d7178c647f63282 \
  --quiesce-sha256 ede42a44edbf798fa9945761887335436766bbd281ddf79635cd686bfe6ffd7b \
  --report "$art/signed-fixes-check.json"
echo 'signed-fixes: PASS'
# The helper packaged in the signed OTA is the one with the new identity.
unzip -p "$ota" recovery-header-sync >"$art/ota-helper.bin"
grep -aq 45344fd27769764622738f99d938ff3cce0d186764c7c23ddc872de292468bf0 "$art/ota-helper.bin"
cmp "$art/ota-helper.bin" <(unzip -p "$release/signed-target-files.zip" SYSTEM/bin/gta3xlwifi_recovery_header_sync)
echo 'signed OTA helper identity: PASS'
python3 - "$fix" "$ota" <<'PY'
import sys, tempfile, importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('pub', Path(sys.argv[1]) / 'publish-ota-index21.py')
pub = importlib.util.module_from_spec(spec); spec.loader.exec_module(pub)
with tempfile.TemporaryDirectory() as t:
    meta = pub.verify_ota(Path(sys.argv[2]), Path(t))
print('updater-ota-verification: PASS', meta['post-build'], meta['post-timestamp'])
PY
python3 "$port/check-signing-inputs.py" /srv/android/signing/arm64-baseline-sha256.json
(cd "$release" && sha256sum "$(basename "$ota")" signed-target-files.zip) >"$art/SIGNED-SHA256SUMS"
cat "$art/SIGNED-SHA256SUMS"
echo 'Built, signed and checked LineageOS 21 with the ABGR TWRP identity.'
