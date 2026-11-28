#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# LineageOS 21 (SM-T510), issue #6: build with the e2fsck fix that ignores the
# Samsung EXT4_POLICY_FLAGS_PRIVATE_ALGO bit when comparing v1 fscrypt policies.
# Produces unsigned target-files and a local test-key OTA for the tablet test.
# Nothing is release-signed or published here.
set -euo pipefail
art=/srv/android/artifacts/los21-issue6-20261128
logs=/srv/android/logs/los21-issue6-20261128
port=/srv/android/ports/lineage-21-arm64
top=/srv/android/src/lineage-21.0-arm64
e2fs=$top/external/e2fsprogs
tf=$top/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
label=e2fsck21-build
exec >"$logs/$label.log" 2>&1
finish() { result=$?; trap - EXIT; printf '%s\n' "$result" >"$logs/$label.exit"; date -u; exit "$result"; }
trap finish EXIT
printf 'Started '; date -u
test "$(cat /srv/android/logs/lineage-21-arm64/full-build.exit)" = 0
test ! -e "$art/build-identity-before"
# Source state: only the reviewed e2fsck change on top of the recorded revision.
test "$(git -C "$e2fs" rev-parse HEAD)" = "$(cat "$art/e2fsprogs-head-before.txt")"
test "$(git -C "$e2fs" status --porcelain)" = " M e2fsck/encrypted_files.c"
test "$(sha256sum "$e2fs/e2fsck/encrypted_files.c" | cut -d' ' -f1)" = c9df17f3cec8981b7372ef9431ae9694013d96466a254ab1674459f102878cdf
cmp <(git -C "$e2fs" diff) "$port/lineage-21/patches/external_e2fsprogs.patch"
# The test-only static tools must not leak into the system image.
test ! -e "$top/out/target/product/gta3xlwifi/system/bin/debugfs_static"
test ! -e "$top/out/target/product/gta3xlwifi/system/bin/e2fsck_static"
mkdir -p "$art/build-identity-before"
for f in build-number-arm64 build-datetime-arm64; do
  if [[ -f $port/lineage-21/$f ]]; then mv "$port/lineage-21/$f" "$art/build-identity-before/$f"; fi
done
export LINEAGE_BUILD_JOBS=16
bash "$port/build-arm64-candidate.sh" >"$logs/stage-build.log" 2>&1
test "$(cat /srv/android/logs/lineage-21-arm64/full-build.exit)" = 0
cat "$port/lineage-21/build-number-arm64"
cp "$tf" "$art/unsigned-target-files.zip"
sha256sum "$art/unsigned-target-files.zip" >"$art/SHA256SUMS"
# The packaged e2fsck must be the patched build, and differ from the released one.
unzip -p "$art/unsigned-target-files.zip" SYSTEM/bin/e2fsck >"$art/e2fsck.bin"
test "$(sha256sum "$art/e2fsck.bin" | cut -d' ' -f1)" = "$(sha256sum "$top/out/target/product/gta3xlwifi/system/bin/e2fsck" | cut -d' ' -f1)"
old=/srv/android/artifacts/lineage-21-arm64/release/signed-target-files.zip
if cmp -s "$art/e2fsck.bin" <(unzip -p "$old" SYSTEM/bin/e2fsck); then
  echo 'e2fsck unchanged from the release' >&2; exit 1
fi
sha256sum "$art/e2fsck.bin" | tee -a "$art/SHA256SUMS"
echo 'patched e2fsck packaged: PASS'
# Nothing else may disappear from the system image compared with the release.
python3 - "$old" "$art/unsigned-target-files.zip" <<'PY'
import sys, zipfile
old = {n for n in zipfile.ZipFile(sys.argv[1]).namelist() if n.startswith(('SYSTEM/', 'PRODUCT/', 'SYSTEM_EXT/', 'VENDOR/'))}
new = {n for n in zipfile.ZipFile(sys.argv[2]).namelist() if n.startswith(('SYSTEM/', 'PRODUCT/', 'SYSTEM_EXT/', 'VENDOR/'))}
print('missing:', sorted(old - new)[:20]); print('added:', sorted(new - old)[:20])
if old - new or new - old:
    raise SystemExit('file set differs from the release')
print('file set identical to the release: PASS')
PY
# Local-only test-key OTA for the tablet test (never published).
(cd "$top" && PATH=$top/out/host/linux-x86/bin:$PATH ota_from_target_files \
  -k build/make/target/product/security/testkey --block --backup=true \
  "$art/unsigned-target-files.zip" "$art/local-testkey-ota-not-for-release.zip") >"$logs/local-test-ota.log" 2>&1
sha256sum "$art/local-testkey-ota-not-for-release.zip" | tee -a "$art/SHA256SUMS"
echo 'Built LineageOS 21 with the e2fsck FBE policy fix (unsigned + local test-key OTA).'
