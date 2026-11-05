#!/usr/bin/env bash
# Resume the stopped explicit module stage; no source/config/image edits.
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
integration=$ports/lineage-24.0
base=$ports/kernel-gator-20261105-01
src=$base/src
out=$base/out
old=/srv/android/src/kernel-gta3xlwifi-dt2w
logs=/srv/android/logs/lineage-24.0-arm64
parent=/srv/android/artifacts/lineage-24.0-arm64/kernel-gator-build-20261105-01
label=kernel-gator-modules-20261105-02
art=/srv/android/artifacts/lineage-24.0-arm64/$label
exec 9>"$logs/build.lock"; flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; date -u; exit "$rc"' EXIT
[[ $(cat "$logs/kernel-gator-build-20261105-01.exit") == 2 && ! -e $art ]]
mkdir "$art"
cp "$integration/experiments/kernel-gator-20261105-01/resume-modules.sh" "$art/runner.sh"
python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-before.json"
python3 "$integration/tools/audit-kernel-tree.py" "$old" "$art/protected-before.json"
python3 - "$parent" "$art" <<'PY'
from pathlib import Path
import json,sys
parent,art=map(Path,sys.argv[1:])
for name in ['source','protected']:
 a=json.loads((parent/(name+'-before.json')).read_text());b=json.loads((art/(name+'-before.json')).read_text())
 for k in ['revision','tree','tracked_sha256','diff_sha256']:assert a[k]==b[k],(name,k)
PY
cp "$parent/vmlinux-Module.symvers-before" "$art/vmlinux-Module.symvers-before"
cp "$parent/kernel.config-before" "$art/kernel.config-before"
cp "$parent/Image-before.sha256" "$art/Image-before.sha256"
cmp "$art/kernel.config-before" "$out/.config"
sha256sum -c "$art/Image-before.sha256"
rg -q '^# CONFIG_MODULE_SIG is not set$' "$out/.config"
export ARCH=arm64 CROSS_COMPILE=/srv/android/toolchains/aarch64-linux-android-4.9/bin/aarch64-linux-android-
export PATH=/srv/android/toolchains/aarch64-linux-android-4.9/bin:$PATH
export PLATFORM_VERSION=11 ANDROID_VERSION=110000 ANDROID_MAJOR_VERSION=r KCFLAGS=-DANDROID_VERSION=110000
export KBUILD_BUILD_USER=oddhap KBUILD_BUILD_HOST=lineage-builder KBUILD_BUILD_VERSION=2
export KBUILD_BUILD_TIMESTAMP='Wed Oct 14 18:00:00 UTC 2026'
make -C "$src" O="$out" -j12 drivers/gator/gator.ko
cmp "$art/kernel.config-before" "$out/.config"
sha256sum -c "$art/Image-before.sha256"
python3 "$integration/experiments/kernel-gator-20261105-01/check-module-versions.py" "$base" "$art" "$art/module-versions.json"
python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-after.json"
python3 "$integration/tools/audit-kernel-tree.py" "$old" "$art/protected-after.json"
python3 - "$art" <<'PY'
from pathlib import Path
import json,sys
p=Path(sys.argv[1])
for n in ['source','protected']:
 a=json.loads((p/(n+'-before.json')).read_text());b=json.loads((p/(n+'-after.json')).read_text())
 for k in ['revision','tree','tracked_sha256','diff_sha256']:assert a[k]==b[k],(n,k)
PY
cp "$out/arch/arm64/boot/Image" "$art/Image"
cp "$out/.config" "$art/kernel.config"
sha256sum "$art/Image" "$art/kernel.config" > "$art/SHA256SUMS"
echo 'Image and both module CRC checks complete; no prebuilt promotion or device validation.'
