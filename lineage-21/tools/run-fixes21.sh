#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# LineageOS 21 (SM-T510): stage the fixes ported from LineageOS 24 (ART CC
# dexpreopt, power-boost retry, SD-card adoptable/exFAT, Updater OTA support),
# build an unsigned candidate and check it. Signing and publication are separate
# owner decisions and are not done here.
set -euo pipefail
job=/srv/android/ports/lineage21-fixes-20261127
art=/srv/android/artifacts/lineage21-fixes-20261127
logs=/srv/android/logs/lineage21-fixes-20261127
port=/srv/android/ports/lineage-21-arm64
top=/srv/android/src/lineage-21.0-arm64
dev=$top/device/samsung/gta3xlwifi
kernel=$art/kernel-exfat21-20261127-01
label=fixes21-build
exec >"$logs/$label.log" 2>&1
finish() { result=$?; trap - EXIT; printf '%s\n' "$result" >"$logs/$label.exit"; date -u; exit "$result"; }
trap finish EXIT
printf 'Started '; date -u
test "$(cat "$logs/kernel-exfat21-20261127-01.exit")" = 0
python3 -c "import json,sys; assert json.load(open(sys.argv[1]))['passed']" "$kernel/report.json"
test ! -e "$art/device-before.tar" && test ! -e "$art/staged"
# The staged device tree must still be the published LineageOS 21 device source.
(cd "$dev" && sha256sum -c "$job/device-original.sha256" --quiet --strict)
test ! -e "$dev/overlay/packages/apps/Updater" && test ! -e "$dev/power/RetryBackoff.h"
# Rollback inputs: complete device tree, source lock and build identity.
tar -C "$dev" -cf "$art/device-before.tar" .
cp "$port/lineage-21/notes/source-inputs.lock.json" "$art/source-inputs.lock.json-before"
mkdir -p "$art/build-identity-before"
for f in build-number-arm64 build-datetime-arm64; do
  if [[ -f $port/lineage-21/$f ]]; then mv "$port/lineage-21/$f" "$art/build-identity-before/$f"; fi
done
# Stage: changed device files, new kernel, kernel lock.
tar -C "$dev" -xf "$job/device-changes.tar"
cp "$kernel/Image" "$dev/prebuilt/Image"
(cd "$dev" && sha256sum -c "$job/device-new.sha256" --quiet --strict)
python3 - "$port/lineage-21/notes/source-inputs.lock.json" "$(sha256sum "$kernel/Image" | cut -d' ' -f1)" <<'PY'
import json, sys
p, new = sys.argv[1], sys.argv[2]
d = json.load(open(p))
assert d['inputs']['kernel_sha256'] == '33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553'
d['inputs']['kernel_sha256'] = new
d['inputs']['kernel_exfat_alias_report'] = '/srv/android/artifacts/lineage21-fixes-20261127/kernel-exfat21-20261127-01/report.json'
open(p, 'w').write(json.dumps(d, indent=2) + '\n')
PY
mkdir "$art/staged"
cp "$port/lineage-21/notes/source-inputs.lock.json" "$art/staged/"
echo 'Staged LineageOS 21 fixes candidate'
export LINEAGE_BUILD_JOBS=16
# Host test for the retry backoff (same test as LineageOS 24 build 51).
bash "$port/build-arm64.sh" gta3xlwifi-power-retry-test gta3xlwifi-power-window-test gta3xlwifi-touch-wake-test >"$logs/host-tests-build.log" 2>&1
for t in gta3xlwifi-power-retry-test gta3xlwifi-power-window-test gta3xlwifi-touch-wake-test; do
  bin=$(find "$top/out/host/linux-x86" -type f -name "$t" -perm -u+x -print -quit)
  test -n "$bin"
  "$bin" >"$logs/$t.log" 2>&1
  echo "$t: PASS"
done
cat "$port/lineage-21/build-number-arm64"
# Normal LineageOS 21 ARM64 build (targeted ABI checks, target-files, otatools).
bash "$port/build-arm64-candidate.sh" >"$logs/stage-build.log" 2>&1
test "$(cat /srv/android/logs/lineage-21-arm64/full-build.exit)" = 0
tf=$top/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
cp "$tf" "$art/unsigned-target-files.zip"
# Local-only test-key OTA to check the generated edify order (never published).
(cd "$top" && PATH=$top/out/host/linux-x86/bin:$PATH ota_from_target_files \
  -k build/make/target/product/security/testkey --block --backup=true \
  "$art/unsigned-target-files.zip" "$art/local-testkey-ota-not-for-release.zip") >"$logs/local-test-ota.log" 2>&1
unzip -p "$art/local-testkey-ota-not-for-release.zip" META-INF/com/google/android/updater-script >"$art/local-test-updater-script.txt"
python3 "$job/check-fixes21.py" "$art/unsigned-target-files.zip" \
  --ota "$art/local-testkey-ota-not-for-release.zip" \
  --kernel-sha256 "$(sha256sum "$kernel/Image" | cut -d' ' -f1)" \
  --vendor-sha256 80aaf6c792e6ab97132f05301db3882316325f54a7776fff4d7178c647f63282 \
  --quiesce-sha256 ede42a44edbf798fa9945761887335436766bbd281ddf79635cd686bfe6ffd7b \
  --report "$art/unsigned-fixes-check.json"
sha256sum "$art/unsigned-target-files.zip" >"$art/SHA256SUMS"
printf 'Finished '; date -u
