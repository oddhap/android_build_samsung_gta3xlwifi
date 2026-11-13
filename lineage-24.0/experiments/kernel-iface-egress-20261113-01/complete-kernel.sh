#!/usr/bin/env bash
# Resume an immutable successful Image compilation after a failed test assumption.
# The first exit1 is retained. No source/config change or prebuilt selection.
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
integration=$ports/lineage-24.0
base=$ports/kernel-iface-egress-20261113-01
src=$base/src
out=$base/out
old=/srv/android/src/kernel-gta3xlwifi-dt2w
root=/srv/android/artifacts/lineage-24.0-arm64
initial=$root/kernel-iface-egress-build-20261113-01
label=kernel-iface-egress-complete-20261113-01
art=$root/$label
logs=/srv/android/logs/lineage-24.0-arm64
exec 9>"$logs/build.lock"
flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
finish(){ result=$?; trap - EXIT; printf '%s\n' "$result" >"$logs/$label.exit"; date -u; exit "$result"; }
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
test "$(cat "$logs/kernel-iface-egress-build-20261113-01.exit")" = 1
mkdir "$art"
python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-before.json"
python3 "$integration/tools/audit-kernel-tree.py" "$old" "$art/protected-before.json"
python3 "$integration/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$integration/snapshots/port-20261106-04" "$art/android-source-before.json"
python3 - "$initial" "$art" "$out" <<'PY'
from pathlib import Path
import hashlib,json,sys
initial,art,out=map(Path,sys.argv[1:]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
for prefix in ['source','protected']:
 values=[json.loads((p/(prefix+'-'+moment+'.json')).read_text()) for p,moment in [(initial,'before'),(initial,'after'),(art,'before')]]
 for key in ['revision','tree','tracked_sha256','diff_sha256']:assert all(x[key]==values[0][key] for x in values),key
for p in sorted(initial.rglob('*.json')):inputs[str(p)]=sha(p)
for n in ['arch/arm64/boot/Image','vmlinux','.config','Module.symvers','init/uh.elf','firmware/exynos7885_acpm_fvp.fw']:inputs[str(out/n)]=sha(out/n)
(art/'resume-provenance.json').write_text(json.dumps({'scope':'Immutable Image-stage resume. Original exit1 retained; failed source-call-count assumption superseded by full normalized ARM64 disassembly comparison. No candidate source change.','inputs_sha256':inputs,'flash_ready':False},indent=2)+'\n')
PY
python3 "$integration/tools/check-iface-egress-relocations24.py" --base-output "$ports/kernel-iface-stats-20261113-02/out" --candidate-output "$out" --objdump /srv/android/toolchains/aarch64-linux-android-4.9/bin/aarch64-linux-android-objdump --output "$art/output-relocations"
export ARCH=arm64
export CROSS_COMPILE=/srv/android/toolchains/aarch64-linux-android-4.9/bin/aarch64-linux-android-
export PATH=/srv/android/toolchains/aarch64-linux-android-4.9/bin:$PATH
export PLATFORM_VERSION=11 ANDROID_VERSION=110000 ANDROID_MAJOR_VERSION=r
export KCFLAGS=-DANDROID_VERSION=110000
export KBUILD_BUILD_USER=oddhap KBUILD_BUILD_HOST=lineage-builder
export KBUILD_BUILD_VERSION=2
export KBUILD_BUILD_TIMESTAMP='Wed Oct 14 18:00:00 UTC 2026'
cmp /srv/android/artifacts/kernel-dt2w/kernel.config "$out/.config"
cp "$out/Module.symvers" "$art/vmlinux-Module.symvers-before"
cp "$out/.config" "$art/kernel.config-before"
sha256sum "$out/arch/arm64/boot/Image" >"$art/Image-before.sha256"
sha256sum -c "$initial/firmware-config.sha256"
rg -q '^# CONFIG_MODULE_SIG is not set$' "$out/.config"
make -C "$src" O="$out" -j12 modules
make -C "$src" O="$out" -j12 drivers/gator/gator.ko
cmp "$art/kernel.config-before" "$out/.config"
sha256sum -c "$art/Image-before.sha256"
python3 "$integration/experiments/kernel-gator-20261105-01/check-module-versions.py" "$base" "$art" "$art/module-versions.json"
python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-after.json"
python3 "$integration/tools/audit-kernel-tree.py" "$old" "$art/protected-after.json"
python3 "$integration/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$integration/snapshots/port-20261106-04" "$art/android-source-after.json"
python3 - "$art" <<'PY'
from pathlib import Path
import json,sys
p=Path(sys.argv[1]);r=json.loads((p/'resume-provenance.json').read_text());import hashlib
for path,h in r['inputs_sha256'].items():assert hashlib.sha256(Path(path).read_bytes()).hexdigest()==h,'Resume input changed: '+path
for prefix in ['source','protected']:
 a=json.loads((p/(prefix+'-before.json')).read_text());b=json.loads((p/(prefix+'-after.json')).read_text())
 for key in ['revision','tree','tracked_sha256','diff_sha256']:assert a[key]==b[key],(prefix,key)
print('PASS: immutable Image, full candidate/protected source and resume input bindings')
PY
cp "$out/arch/arm64/boot/Image" "$art/Image"
cp "$out/.config" "$art/kernel.config"
sha256sum "$art/Image" "$art/kernel.config" >"$art/SHA256SUMS"
