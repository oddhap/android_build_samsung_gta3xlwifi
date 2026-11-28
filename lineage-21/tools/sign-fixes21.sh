#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# LineageOS 21 (SM-T510): release-sign the fixes candidate with the existing
# LineageOS 21 keys (sign-release.py, keys never copied or printed) and run the
# same thirteen offline checks, vendor policy/VINTF and GApps capacity checks as
# the 2026-11-24 release, plus the fixes check on the signed output.
# Nothing is published here.
set -euo pipefail
job=/srv/android/ports/lineage21-fixes-20261127
art=/srv/android/artifacts/lineage21-fixes-20261127
logs=/srv/android/logs/lineage21-fixes-20261127
port=/srv/android/ports/lineage-21-arm64
notes=$port/lineage-21
top=/srv/android/src/lineage-21.0-arm64
base=/srv/android/artifacts/lineage-21-arm64
release=$base/release
gapps=/srv/android/artifacts/gapps-arm64/MindTheGapps-14.0.0-arm64-20250203_200051.zip
simg2img=$top/out/host/linux-x86/bin/simg2img
original=$top/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
label=sign-fixes21
exec >"$logs/$label.log" 2>&1
finish() { result=$?; trap - EXIT; printf '%s\n' "$result" >"$logs/$label.exit"; date -u; exit "$result"; }
trap finish EXIT
printf 'Started '; date -u
test "$(cat "$logs/fixes21-check.exit")" = 0  # build + check (resume-check21.sh)
test "$(cat /srv/android/logs/lineage-21-arm64/full-build.exit)" = 0
# The build output must still be exactly the checked unsigned candidate.
test "$(sha256sum "$original" | cut -d' ' -f1)" = "$(cut -d' ' -f1 "$art/SHA256SUMS")"
python3 "$port/check-signing-inputs.py" /srv/android/signing/arm64-baseline-sha256.json
# Keep the published 2026-11-24 release outputs as the rollback/baseline input.
test ! -e "$art/release-before" && test ! -e "$art/pre-sign"
mv "$release" "$art/release-before"
python3 "$notes/tools/verify-gapps-headroom.py" --release "$art/pre-sign" --target-files "$original" \
  --gapps "$gapps" --simg2img "$simg2img" \
  --baseline-target-files "$art/release-before/signed-target-files.zip" >"$logs/unsigned-gapps-headroom.log" 2>&1
echo 'unsigned-gapps-headroom: PASS'
python3 "$notes/tools/sign-release.py" "$original" >"$logs/signing.log" 2>&1
echo 'signing: PASS'
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
# The ported fixes and the OTA script order in the signed output.
python3 "$job/check-fixes21.py" "$release/signed-target-files.zip" --ota "$ota" \
  --kernel-sha256 c7b4a44fcb4f31ea53d86fe000270d6a20d0f9d3e5a84ae9249c9d0acba19aca \
  --vendor-sha256 80aaf6c792e6ab97132f05301db3882316325f54a7776fff4d7178c647f63282 \
  --quiesce-sha256 ede42a44edbf798fa9945761887335436766bbd281ddf79635cd686bfe6ffd7b \
  --report "$art/signed-fixes-check.json"
echo 'signed-fixes: PASS'
# The same OTA verification the Updater index publisher applies before publishing.
python3 - "$job" "$ota" <<'PY'
import sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import importlib.util
spec = importlib.util.spec_from_file_location('pub', Path(sys.argv[1]) / 'publish-ota-index21.py')
pub = importlib.util.module_from_spec(spec); spec.loader.exec_module(pub)
with tempfile.TemporaryDirectory() as t:
    meta = pub.verify_ota(Path(sys.argv[2]), Path(t))
print('updater-ota-verification: PASS', meta['post-build'], meta['post-timestamp'])
PY
python3 "$port/check-signing-inputs.py" /srv/android/signing/arm64-baseline-sha256.json
(cd "$release" && sha256sum "$(basename "$ota")" signed-target-files.zip) >"$art/SIGNED-SHA256SUMS"
cat "$art/SIGNED-SHA256SUMS"
echo 'Signed package, thirteen offline checks, vendor policy/VINTF, GApps capacity and fixes check pass.'
