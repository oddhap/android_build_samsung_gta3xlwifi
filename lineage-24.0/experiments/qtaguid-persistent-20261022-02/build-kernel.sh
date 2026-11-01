#!/usr/bin/env bash
# Isolated diagnostic kernel build. Never updates the Android prebuilt or tablet.
set -euo pipefail
base=/srv/android/ports/lineage-23.2-arm64/kernel-socket-owned-20261022-01
src=$base/src3
out=$base/out3
art=/srv/android/artifacts/lineage-23.2-arm64/kernel-socket-owned-20261022-03
old=/srv/android/src/kernel-gta3xlwifi-dt2w
staged=/srv/android/ports/lineage-23.2-arm64/network-work-20261020-01/kernel/samsung/gta3xlwifi
label=kernel-socket-owned-03
logs=/srv/android/logs/lineage-23.2-arm64
exec 9>"$logs/build.lock"
flock -n 9 || { echo 'Another build/audit holds build.lock'; exit 75; }
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; date -u; exit "$result"' EXIT
printf 'Started '; date -u
export PATH=/srv/android/toolchains/aarch64-linux-android-4.9/bin:$PATH
test "$(git -C "$src" rev-parse HEAD)" = efbdbfa3e216b0c300d381c340b0a22b24e15c13
test ! -f "$src/.git/objects/info/alternates"
test -z "$(git -C "$src" status --porcelain --untracked-files=all)"
test ! -e "$out" && test ! -e "$art"
# The archived touch patch is only a subset: input_set_enabled in input.c/h
# was an additional base prerequisite already present in the actual linked
# preserved kernel. Capture the COMPLETE read-only four-file working delta,
# refuse any other edits, and retain both inputs instead of guessing/resetting.
touch_patch=/srv/android/artifacts/kernel-dt2w/kernel-double-tap-wake.patch
git -C "$old" apply --reverse --check "$touch_patch"
complete_touch=$base/baseline-touch-complete-03.patch
python3 - "$old" "$complete_touch" <<'PY'
import subprocess,sys
from pathlib import Path
old,out=sys.argv[1:]
expected={'drivers/input/input.c','include/linux/input.h',
 'drivers/input/touchscreen/stm_fts1ba90a/fts_sec.c',
 'drivers/input/touchscreen/stm_fts1ba90a/fts_ts.c'}
actual=set(subprocess.check_output(['git','-C',old,'diff','--name-only'],text=True).splitlines())
assert actual==expected,(actual,expected)
p=Path(out);assert not p.exists()
p.write_bytes(subprocess.check_output(['git','-C',old,'diff','--binary']))
PY
git -C "$src" apply --check "$complete_touch"
git -C "$src" apply "$complete_touch"
for file in drivers/input/input.c include/linux/input.h \
    drivers/input/touchscreen/stm_fts1ba90a/fts_sec.c \
    drivers/input/touchscreen/stm_fts1ba90a/fts_ts.c; do
    cmp "$src/$file" "$old/$file"
done
# Verify unchanged qtaguid inputs against known preserved source before copying
# precisely the separately host-tested new implementation and private UAPI.
for file in net/netfilter/xt_qtaguid.c net/netfilter/xt_qtaguid_internal.h; do
    cmp "$src/$file" "$old/$file"
    cp "$staged/$file" "$src/$file"
done
file=include/uapi/linux/netfilter/xt_qtaguid_sock.h
test ! -e "$src/$file"
cp "$staged/$file" "$src/$file"
mkdir -p "$out/init" "$out/firmware" "$art"
# Existing Samsung firmware inputs, not signing keys. Hashes captured below.
cp "$old/init/uh.elf" "$out/init/uh.elf"
cp "$old/firmware/exynos7885_acpm_fvp.fw" "$out/firmware/exynos7885_acpm_fvp.fw"
cp /srv/android/artifacts/kernel-dt2w/kernel.config "$out/.config"
export ARCH=arm64
export CROSS_COMPILE=/srv/android/toolchains/aarch64-linux-android-4.9/bin/aarch64-linux-android-
export PLATFORM_VERSION=11 ANDROID_VERSION=110000 ANDROID_MAJOR_VERSION=r
export KCFLAGS=-DANDROID_VERSION=110000
export KBUILD_BUILD_USER=oddhap KBUILD_BUILD_HOST=lineage-builder
export KBUILD_BUILD_VERSION=2
export KBUILD_BUILD_TIMESTAMP='Wed Oct 14 18:00:00 UTC 2026'
# Preserve the firmware/config and exact patch inputs used by this experiment.
sha256sum "$out/init/uh.elf" "$out/firmware/exynos7885_acpm_fvp.fw" "$out/.config" \
    "$touch_patch" "$complete_touch" "$src/net/netfilter/xt_qtaguid.c" "$src/net/netfilter/xt_qtaguid_internal.h" \
    "$src/include/uapi/linux/netfilter/xt_qtaguid_sock.h" >"$art/inputs.sha256"
git -C "$src" diff --binary >"$art/tracked-source.patch"
cp "$src/include/uapi/linux/netfilter/xt_qtaguid_sock.h" "$art/xt_qtaguid_sock.h"
cp "$complete_touch" "$art/baseline-touch-complete.patch"
make -C "$src" O="$out" olddefconfig
make -C "$src" O="$out" silentoldconfig
cmp /srv/android/artifacts/kernel-dt2w/kernel.config "$out/.config"
make -C "$src" O="$out" -j12 Image
cp "$out/arch/arm64/boot/Image" "$art/Image"
cp "$out/.config" "$art/kernel.config"
sha256sum "$art/Image" "$art/kernel.config" >"$art/SHA256SUMS"
printf '%s\n' 'EXPERIMENTAL — NOT IN ANDROID PREBUILT. NO FLASH APPROVAL. Kernel link only; live lifecycle, full networking, security, FBE/recovery/OTA are unproven.' >"$art/NOT_READY_FOR_FLASHING.txt"
printf 'Finished '; date -u
