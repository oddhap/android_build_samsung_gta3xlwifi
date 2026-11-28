#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# LineageOS 21 (SM-T510), issue #6: release-sign the e2fsck FBE policy fix build
# (run-e2fsck21.sh) with the existing LineageOS 21 keys and run the same checks as
# the 2026-11-28 TWRP release. Nothing is published here.
set -euo pipefail
art=/srv/android/artifacts/los21-issue6-20261128
logs=/srv/android/logs/los21-issue6-20261128
fix=/srv/android/ports/lineage21-fixes-20261127
port=/srv/android/ports/lineage-21-arm64
notes=$port/lineage-21
top=/srv/android/src/lineage-21.0-arm64
base=/srv/android/artifacts/lineage-21-arm64
release=$base/release
gapps=/srv/android/artifacts/gapps-arm64/MindTheGapps-14.0.0-arm64-20250203_200051.zip
simg2img=$top/out/host/linux-x86/bin/simg2img
tf=$top/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
label=e2fsck21-sign
exec >"$logs/$label.log" 2>&1
finish() { result=$?; trap - EXIT; printf '%s\n' "$result" >"$logs/$label.exit"; date -u; exit "$result"; }
trap finish EXIT
printf 'Started '; date -u
test "$(cat "$logs/e2fsck21-build.exit")" = 0
test ! -e "$art/release-before"
# The out tree must still hold exactly the tested build.
test "$(sha256sum "$tf" | cut -d' ' -f1)" = dcd8edb37a5406cafbd124ba1bbcfcc8c1122a41d20d59e26a1e15f8217a679f
test "$(cat "$port/lineage-21/build-number-arm64")" = gta3xlwifi.arm64.20261128.104453
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
# The signed system carries the patched e2fsck (the binary tested on the tablet).
test "$(unzip -p "$release/signed-target-files.zip" SYSTEM/bin/e2fsck | sha256sum | cut -d' ' -f1)" = \
  ad0821dd331c8f1c41bb53db912ea6d0840bf83334d0d617b7cf7e0675e48f4e
echo 'signed e2fsck: PASS'
# The OTA recovery-header helper keeps the ABGR TWRP identity of the previous release.
unzip -p "$ota" recovery-header-sync >"$art/ota-helper.bin"
grep -aq 45344fd27769764622738f99d938ff3cce0d186764c7c23ddc872de292468bf0 "$art/ota-helper.bin"
cmp "$art/ota-helper.bin" <(unzip -p "$release/signed-target-files.zip" SYSTEM/bin/gta3xlwifi_recovery_header_sync)
echo 'signed OTA helper identity: PASS'
old_ota=$(ls "$art"/release-before/lineage-21.0-*-UNOFFICIAL-gta3xlwifi-arm64-privatekeys.zip)
python3 - "$fix" "$ota" "$old_ota" <<'PY'
import sys, tempfile, importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('pub', Path(sys.argv[1]) / 'publish-ota-index21.py')
pub = importlib.util.module_from_spec(spec); spec.loader.exec_module(pub)
with tempfile.TemporaryDirectory() as t:
    meta = pub.verify_ota(Path(sys.argv[2]), Path(t))
with tempfile.TemporaryDirectory() as t:
    old = pub.verify_ota(Path(sys.argv[3]), Path(t))
# The Updater only offers a package newer than the installed build.
assert int(meta['post-timestamp']) > int(old['post-timestamp']), (meta['post-timestamp'], old['post-timestamp'])
print('updater-ota-verification: PASS', meta['post-build'], meta['post-timestamp'], '>', old['post-timestamp'])
PY
python3 "$port/check-signing-inputs.py" /srv/android/signing/arm64-baseline-sha256.json
(cd "$release" && sha256sum "$(basename "$ota")" signed-target-files.zip) >"$art/SIGNED-SHA256SUMS"
cat "$art/SIGNED-SHA256SUMS"
echo 'Signed and checked LineageOS 21 with the e2fsck FBE policy fix.'
