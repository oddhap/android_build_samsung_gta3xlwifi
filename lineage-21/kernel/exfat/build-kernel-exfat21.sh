#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# LineageOS 21 (SM-T510): isolated kernel candidate = the released DT2W kernel
# source plus the sdfat "exfat" filesystem alias from LineageOS 24 build 53
# (GitHub issue 4). First proves the copy reproduces the released Image
# (33c1a0d1...), then applies only fs/sdfat/sdfat.c and rebuilds.
# The original kernel tree, output and device prebuilts are never modified.
set -euo pipefail
label=kernel-exfat21-20261127-01
job=/srv/android/ports/lineage21-fixes-20261127
orig=/srv/android/src/kernel-gta3xlwifi-dt2w
released=/srv/android/artifacts/kernel-dt2w
patchdir=/srv/android/ports/lineage-24.0-arm64/kernel-sdfat-exfat24-20261123-01
tools24=/srv/android/ports/lineage-24.0-arm64/lineage-24.0/tools
# Same path lengths as the released build (/srv/android/src/kernel-gta3xlwifi-dt2w,
# O=/srv/android/out/kernel-dt2w): __FILE__ strings then differ only in bytes,
# so the reproduction can be proven exactly by substituting the paths back.
base=/srv/android/ports/l21fx1127-kernel
src=$base/src
out=/srv/android/ports/l21fx-out
orig_out=/srv/android/out/kernel-dt2w
art=/srv/android/artifacts/lineage21-fixes-20261127/$label
logs=/srv/android/logs/lineage21-fixes-20261127
mkdir -p "$logs"
exec 9>/srv/android/logs/lineage-21-arm64/build.lock
flock -n 9 || { echo 'Another LineageOS 21 build is active.' >&2; exit 75; }
exec >"$logs/$label.log" 2>&1
finish() {
  result=$?; trap - EXIT
  if [[ -f $art/original-before.json && ! -f $art/original-after.json ]]; then
    python3 "$tools24/audit-kernel-tree.py" "$orig" "$art/original-after.json" || result=1
  fi
  printf '%s\n' "$result" >"$logs/$label.exit"; date -u; exit "$result"
}
trap finish EXIT
printf 'Started '; date -u
test ! -e "$base" && test ! -e "$out" && test ! -e "$art"
test ${#src} = ${#orig} && test ${#out} = ${#orig_out}
mkdir -p "$art" "$base"
echo "$base $out" >"$job/kernel-build-dirs.txt"
released_sha=33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553
echo "$released_sha  $released/Image" | sha256sum -c
echo "d318d21c7c7f818fe480c85966f2eaeb42381c268eef9e3e01418de75a83c7a5  $orig/fs/sdfat/sdfat.c" | sha256sum -c
echo "e3ffcd8e7f35cf9279898ec1e845c01c946e221d7276ae4b12a09627ae24e0cf  $patchdir/sdfat-exfat-alias.patch" | sha256sum -c
python3 "$tools24/audit-kernel-tree.py" "$orig" "$art/original-before.json"
# Refuse signing-material filenames instead of reading or copying them.
if [ -n "$(find "$orig" -path "$orig/.git" -prune -o -type f \( -iname '*.pem' -o -iname '*.key' -o -iname '*.p12' -o -iname '*.pfx' -o -iname '*.keystore' -o -iname '*.jks' \) -print -quit)" ]; then
  echo 'Signing-material filenames in kernel tree; refusing to copy.' >&2; exit 1
fi
rsync -a --exclude=/.git "$orig/" "$src/"
diff -r --no-dereference --exclude=.git -q "$orig" "$src"
export ARCH=arm64
export CROSS_COMPILE=/srv/android/toolchains/aarch64-linux-android-4.9/bin/aarch64-linux-android-
export PATH=/srv/android/toolchains/aarch64-linux-android-4.9/bin:$PATH
export PLATFORM_VERSION=11 ANDROID_VERSION=110000 ANDROID_MAJOR_VERSION=r
export KCFLAGS=-DANDROID_VERSION=110000
export KBUILD_BUILD_USER=oddhap KBUILD_BUILD_HOST=lineage-builder
export KBUILD_BUILD_VERSION=2
export KBUILD_BUILD_TIMESTAMP='Wed Oct 14 18:00:00 UTC 2026'
# The released kernel was built from the Git checkout (setlocalversion: efbdbfa3, dirty);
# the copy has no .git, so give the identical release string explicitly (module vermagic).
grep -aq 'Linux version 4.4.302-gefbdbfa3-dirty (oddhap@lineage-builder)' "$released/Image"
export LOCALVERSION=-gefbdbfa3-dirty
mkdir -p "$out/init" "$out/firmware"
cp "$orig/init/uh.elf" "$out/init/uh.elf"
cp "$orig/firmware/exynos7885_acpm_fvp.fw" "$out/firmware/exynos7885_acpm_fvp.fw"
cp "$released/kernel.config" "$out/.config"
make -C "$src" O="$out" olddefconfig
cmp "$released/kernel.config" "$out/.config"
# 1) Reproduction: the unmodified copy must give the released Image.
make -C "$src" O="$out" -j16 Image
sha256sum "$out/arch/arm64/boot/Image" | tee "$art/reproduced-Image.sha256"
repro=$(sha256sum "$out/arch/arm64/boot/Image" | cut -d' ' -f1)
python3 - "$out/arch/arm64/boot/Image" "$released/Image" "$src" "$orig" "$out" "$orig_out" "$art/reproduction.json" <<'PY2'
import hashlib, json, sys
new, old, src, orig, out, orig_out, rep = sys.argv[1:]
d = open(new, 'rb').read(); o = open(old, 'rb').read()
n_src, n_out = d.count(src.encode()), d.count(out.encode())
fixed = d.replace(src.encode(), orig.encode()).replace(out.encode(), orig_out.encode())
# The GNU build-id is a SHA-1 over the linked bytes, which contain the source path;
# it is the only field allowed to differ (exactly one NT_GNU_BUILD_ID note, same offset).
note = b'\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00'
assert o.count(note) == 1 and fixed.count(note) == 1 and o.index(note) == fixed.index(note)
i = o.index(note) + len(note)
mask = lambda b: b[:i] + bytes(20) + b[i + 20:]
r = {'size_equal': len(d) == len(o), 'source_path_occurrences': n_src, 'output_path_occurrences': n_out,
     'build_id_offset': i, 'released_build_id': o[i:i + 20].hex(), 'copy_build_id': fixed[i:i + 20].hex(),
     'identical_after_path_substitution': mask(fixed) == mask(o)}
open(rep, 'w').write(json.dumps(r, indent=2) + '\n'); print(r)
assert r['identical_after_path_substitution'], 'copy does not reproduce the released Image'
PY2
reproduced=true
echo "reproduced_released_image=$reproduced"
{ "${CROSS_COMPILE}nm" "$out/vmlinux" | grep ' __crc_' || true; } | sort >"$art/crc-before.txt"
# 2) Candidate: only fs/sdfat/sdfat.c changes.
patch -d "$src" -p1 --no-backup-if-mismatch <"$patchdir/sdfat-exfat-alias.patch"
echo "46a0f9926bc5fc142b53e137d9640a7de227a25b0ddd0c0232a5a5243e89b67f  $src/fs/sdfat/sdfat.c" | sha256sum -c
changed=$(diff -r --no-dereference --exclude=.git -q "$orig" "$src" || true)
echo "$changed"
test "$(printf '%s\n' "$changed" | wc -l)" = 1
[[ $changed == *"fs/sdfat/sdfat.c"* ]]
python3 "$tools24/test-kernel-sdfat-exfat24.py" --source "$src" --output "$art/host"
make -C "$src" O="$out" -j16 Image
cmp "$released/kernel.config" "$out/.config"
"${CROSS_COMPILE}nm" "$out/vmlinux" >"$art/vmlinux-symbols.txt"
grep -Eq ' [dD] exfat_fs_type$' "$art/vmlinux-symbols.txt"
grep -Eq ' [dD] sdfat_fs_type$' "$art/vmlinux-symbols.txt"
{ grep ' __crc_' "$art/vmlinux-symbols.txt" || true; } | sort >"$art/crc-after.txt"
cmp "$art/crc-before.txt" "$art/crc-after.txt"
cp "$out/arch/arm64/boot/Image" "$art/Image"
grep -aq 'Linux version 4.4.302-gefbdbfa3-dirty (oddhap@lineage-builder)' "$art/Image"
cp "$out/.config" "$art/kernel.config"
python3 "$tools24/audit-kernel-tree.py" "$orig" "$art/original-after.json"
python3 - "$art" "$released_sha" "$reproduced" <<'PY'
import json, sys, hashlib
from pathlib import Path
art, released, reproduced = Path(sys.argv[1]), sys.argv[2], sys.argv[3] == 'true'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
a = json.loads((art/'original-before.json').read_text()); b = json.loads((art/'original-after.json').read_text())
for k in ['revision', 'tree', 'tracked_sha256', 'diff_sha256', 'status']:
    assert a[k] == b[k], k
host = json.loads((art/'host/report.json').read_text()); assert host['passed']
image = sha(art/'Image'); assert image != released
(art/'report.json').write_text(json.dumps({
    'passed': True,
    'scope': 'Released LineageOS 21 DT2W kernel plus sdfat exfat alias (fs/sdfat/sdfat.c only; issue 4)',
    'baseline_source': '/srv/android/src/kernel-gta3xlwifi-dt2w (unchanged, audited before/after)',
    'released_Image_sha256': released,
    'copy_reproduces_released_Image_after_build_path_substitution_except_gnu_build_id': reproduced,
    'build_paths': 'same-length copy paths; release string 4.4.302-gefbdbfa3-dirty kept',
    'Image_sha256': image,
    'kernel_config_identical_to_released': True,
    'exported_symbol_crcs_unchanged': True,
    'host_sdfat_exfat_cases': host.get('passed_cases'),
    'hardware_tested': False}, indent=2) + '\n')
PY
sha256sum "$art/Image" "$art/kernel.config" >"$art/SHA256SUMS"
printf 'Finished '; date -u
