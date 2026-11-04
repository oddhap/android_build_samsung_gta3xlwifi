#!/usr/bin/env bash
# Build only in the already isolated candidate; no module installation/load.
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
integration=$ports/lineage-24.0
base=$ports/kernel-perf-20261104-01
src=$base/src
out=$base/out
logs=/srv/android/logs/lineage-24.0-arm64
art=/srv/android/artifacts/lineage-24.0-arm64/kernel-perf-modules-20261104-02
label=kernel-perf-modules-20261104-02
exec 9>"$logs/build.lock"
flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; date -u; exit "$result"' EXIT
test "$(cat "$logs/kernel-perf-build-20261104-01.exit")" = 0
test "$(cat "$logs/kernel-perf-host-20261104-01.exit")" = 0
test ! -e "$art"
mkdir "$art"
printf '%s\n' 'DIAGNOSTIC MODULES ONLY. No install, device load, signing or Android prebuilt promotion.' >"$art/NOT_READY_FOR_FLASHING.txt"
python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-before.json"
cp "$out/Module.symvers" "$art/vmlinux-Module.symvers-before"
cp "$out/.config" "$art/kernel.config-before"
sha256sum "$out/arch/arm64/boot/Image" >"$art/Image-before.sha256"
rg -q '^# CONFIG_MODULE_SIG is not set$' "$out/.config"
export ARCH=arm64
export CROSS_COMPILE=/srv/android/toolchains/aarch64-linux-android-4.9/bin/aarch64-linux-android-
export PATH=/srv/android/toolchains/aarch64-linux-android-4.9/bin:$PATH
export PLATFORM_VERSION=11 ANDROID_VERSION=110000 ANDROID_MAJOR_VERSION=r
export KCFLAGS=-DANDROID_VERSION=110000
export KBUILD_BUILD_USER=oddhap KBUILD_BUILD_HOST=lineage-builder KBUILD_BUILD_VERSION=2
export KBUILD_BUILD_TIMESTAMP='Wed Oct 14 18:00:00 UTC 2026'
make -C "$src" O="$out" -j12 modules
# Samsung drivers/Makefile only descends into gator for CONFIG_GATOR=y.
# Explicit module target honors the preserved CONFIG_GATOR=m without edits.
make -C "$src" O="$out" -j12 M=drivers/gator modules
cmp "$art/kernel.config-before" "$out/.config"
sha256sum -c "$art/Image-before.sha256"
python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-after.json"
python3 - "$art" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]);a=json.loads((p/'source-before.json').read_text());b=json.loads((p/'source-after.json').read_text())
for k in ['revision','tree','tracked_sha256','diff_sha256']:assert a[k]==b[k],k
print('PASS: complete tracked candidate source unchanged during module build')
PY
cp "$out/Module.symvers" "$art/Module.symvers-after"
date -u
