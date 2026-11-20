#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Isolated kernel candidate: active UID-receipt kernel + netpolicy flush identity
# fix (debuggerd pseudothread must not revoke the netd lease). No selected
# source, prebuilt or device promotion happens here.
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
integration=$ports/lineage-24.0
baseline=$ports/kernel-uid-receipt-20261115-01
staging=$ports/kernel-netpolicy-flush24-20261120-01
base=$ports/kernel-netpolicy-flush-20261120-01
src=$base/src
out=$base/out
old=/srv/android/src/kernel-gta3xlwifi-dt2w
top=/srv/android/src/lineage-24.0-arm64
label=kernel-netpolicy-flush-build-20261120-01
art=/srv/android/artifacts/lineage-24.0-arm64/$label
active=/srv/android/artifacts/lineage-24.0-arm64/kernel-uid-receipt-build-20261115-01
logs=/srv/android/logs/lineage-24.0-arm64
exec 9>"$logs/build.lock"
flock -n 9 || exit 75
exec >"$logs/$label.log" 2>&1
finish() {
 result=$?; trap - EXIT
 for pair in 'source:'"$src" 'protected:'"$old" 'baseline:'"$baseline/src"; do
  prefix=${pair%%:*}; tree=${pair#*:}
  if [[ -f $art/$prefix-before.json && ! -f $art/$prefix-after.json ]]; then
   python3 "$integration/tools/audit-kernel-tree.py" "$tree" "$art/$prefix-after.json" || result=1
  fi
 done
 if [[ -f $art/android-before.json && ! -f $art/android-after.json ]]; then
  python3 "$integration/tools/audit-port.py" "$top" "$integration/snapshots/port-20261120-32" "$art/android-after.json" || result=1
 fi
 printf '%s\n' "$result" >"$logs/$label.exit"
 date -u
 exit "$result"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
printf 'Started '; date -u
test ! -e "$base" && test ! -e "$art"
mkdir "$art"
python3 "$integration/tools/audit-kernel-tree.py" "$old" "$art/protected-before.json"
python3 "$integration/tools/audit-kernel-tree.py" "$baseline/src" "$art/baseline-before.json"
python3 "$integration/tools/audit-port.py" "$top" "$integration/snapshots/port-20261120-32" "$art/android-before.json"
python3 - "$baseline/src" "$staging" "$base" "$art" "$active" <<'PY'
from pathlib import Path
import shutil,hashlib,json,sys
original,staging,base,art,active=map(Path,sys.argv[1:]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
private=[str(p.relative_to(original)) for p in original.rglob('*') if p.is_file() and p.suffix.lower() in {'.pem','.key','.p12','.pfx','.keystore','.jks'}]
assert not private,('Signing-material filenames require excluding, never reading',private)
assert not (original/'.git/objects/info/alternates').exists()
assert json.loads((active/'report.json').read_text())['passed']
locks=json.loads((staging/'baseline.json').read_text());assert list(locks['original_sha256'])==['net/netfilter/gta3xlwifi_netpolicy.c']
for name,h in locks['original_sha256'].items():
 assert sha(original/name)==h and sha(staging/(name+'.reference'))==h
 assert sha(staging/name)==locks['candidate_sha256'][name]
shutil.copytree(original,base/'src',symlinks=True)
for name in locks['original_sha256']:
 target=base/'src'/name;assert sha(target)==locks['original_sha256'][name];shutil.copyfile(staging/name,target)
(art/'overlay-lock.json').write_text(json.dumps({'baseline_kernel':str(original),'active_kernel_build_report_sha256':sha(active/'report.json'),'baseline':locks,'copied_signing_material':False,'baseline_output_copied':False},indent=2)+'\n')
PY
python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-before.json"
python3 "$integration/tools/test-kernel-netpolicy-flush24.py" --source "$src" --output "$art/host"
export ARCH=arm64
export CROSS_COMPILE=/srv/android/toolchains/aarch64-linux-android-4.9/bin/aarch64-linux-android-
export PATH=/srv/android/toolchains/aarch64-linux-android-4.9/bin:$PATH
export PLATFORM_VERSION=11 ANDROID_VERSION=110000 ANDROID_MAJOR_VERSION=r
export KCFLAGS=-DANDROID_VERSION=110000
export KBUILD_BUILD_USER=oddhap KBUILD_BUILD_HOST=lineage-builder
export KBUILD_BUILD_VERSION=2
export KBUILD_BUILD_TIMESTAMP='Wed Oct 14 18:00:00 UTC 2026'
mkdir -p "$out/init" "$out/firmware"
cp "$old/init/uh.elf" "$out/init/uh.elf"
cp "$old/firmware/exynos7885_acpm_fvp.fw" "$out/firmware/exynos7885_acpm_fvp.fw"
cp /srv/android/artifacts/kernel-dt2w/kernel.config "$out/.config"
rg -q '^# CONFIG_MODULE_SIG is not set$' "$out/.config"
rg -q '^CONFIG_NETFILTER_XT_MATCH_QTAGUID=y$' "$out/.config"
sha256sum "$out/.config" "$out/init/uh.elf" "$out/firmware/exynos7885_acpm_fvp.fw" >"$art/config-firmware.sha256"
make -C "$src" O="$out" olddefconfig
make -C "$src" O="$out" silentoldconfig
cmp /srv/android/artifacts/kernel-dt2w/kernel.config "$out/.config"
cmp "$active/kernel.config" "$out/.config"
make -C "$src" O="$out" -j12 Image
"${CROSS_COMPILE}nm" "$out/vmlinux" >"$art/vmlinux-symbols.txt"
for symbol in gta3xlwifi_packet_stats_cleanup_pending gta3xlwifi_iface_names_features gta3xlwifi_iface_stats_ioctl gta3xlwifi_packet_stats_record gta3xlwifi_runtime_ioctl gta3xlwifi_netpolicy_held; do
 rg -q " T $symbol$" "$art/vmlinux-symbols.txt"
done
rg -q ' [bd] netpolicy_owner_files$' "$art/vmlinux-symbols.txt"
"${CROSS_COMPILE}objdump" -dr "$out/net/netfilter/gta3xlwifi_netpolicy.o" >"$art/netpolicy-disassembly.txt"
cp "$out/Module.symvers" "$art/vmlinux-Module.symvers-before"
cp "$out/.config" "$art/kernel.config-before"
sha256sum "$out/arch/arm64/boot/Image" >"$art/Image-before.sha256"
make -C "$src" O="$out" -j12 modules
make -C "$src" O="$out" -j12 drivers/gator/gator.ko
cmp "$art/kernel.config-before" "$out/.config"
sha256sum -c "$art/Image-before.sha256"
python3 "$integration/experiments/kernel-gator-20261105-01/check-module-versions.py" "$base" "$art" "$art/module-versions.json"
for pair in 'source:'"$src" 'protected:'"$old" 'baseline:'"$baseline/src"; do
 prefix=${pair%%:*}; tree=${pair#*:}
 python3 "$integration/tools/audit-kernel-tree.py" "$tree" "$art/$prefix-after.json"
done
python3 "$integration/tools/audit-port.py" "$top" "$integration/snapshots/port-20261120-32" "$art/android-after.json"
cp "$out/arch/arm64/boot/Image" "$art/Image"
cp "$out/.config" "$art/kernel.config"
python3 - "$art" "$active" <<'PY'
import json,sys,hashlib
from pathlib import Path
p,active=map(Path,sys.argv[1:]);sha=lambda q:hashlib.sha256(q.read_bytes()).hexdigest()
for prefix in ['source','protected','baseline']:
 a=json.loads((p/(prefix+'-before.json')).read_text());b=json.loads((p/(prefix+'-after.json')).read_text())
 for key in ['revision','tree','tracked_sha256','diff_sha256']:assert a[key]==b[key],(prefix,key)
host=json.loads((p/'host/report.json').read_text());assert host['passed'] and host['passed_cases']==48
assert sha(p/'Image')!=sha(active/'Image') and sha(p/'kernel.config')==sha(active/'kernel.config')
(p/'report.json').write_text(json.dumps({'passed':True,'scope':'Active UID-receipt kernel plus netpolicy flush descriptor-table identity only','actual_Image_all_modules_and_Gator_built':True,'complete_source_protected_baseline_Android_audits':True,'host_flush_cases':48,'host_report_sha256':sha(p/'host/report.json'),'kernel_config_identical_to_active':True,'previous_Image_sha256':sha(active/'Image'),'Image_sha256':sha(p/'Image'),'selected_prebuilts_changed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n')
PY
sha256sum "$art/Image" "$art/kernel.config" >"$art/SHA256SUMS"
printf 'Finished '; date -u
