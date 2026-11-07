#!/usr/bin/env bash
# Isolated diagnostic build only. Does NOT update TOP/prebuilt or any device.
set -euo pipefail
ports=/srv/android/ports/lineage-24.0-arm64
integration=$ports/lineage-24.0
base=$ports/kernel-uid-permissions-20261107-01
src=$base/src
out=$base/out
old=/srv/android/src/kernel-gta3xlwifi-dt2w
label=kernel-uid-permissions-build-20261107-01
art=/srv/android/artifacts/lineage-24.0-arm64/$label
logs=/srv/android/logs/lineage-24.0-arm64
exec 9>"$logs/build.lock"
flock -n 9 || { echo 'Another build/audit holds build.lock'; exit 75; }
exec >"$logs/$label.log" 2>&1
finish() {
 result=$?; trap - EXIT
 if [[ -f $art/android-source-before.json && ! -e $art/android-source-after.json ]]; then
  python3 "$integration/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$integration/snapshots/port-20261106-04" "$art/android-source-after.json" || result=1
 fi
 if [[ -f $art/source-before.json && ! -e $art/source-after.json ]]; then
  python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-after.json" || result=1
 fi
 if [[ -f $art/protected-before.json && ! -e $art/protected-after.json ]]; then
  python3 "$integration/tools/audit-kernel-tree.py" "$old" "$art/protected-after.json" || result=1
 fi
 printf '%s\n' "$result" > "$logs/$label.exit"
 date -u
 exit "$result"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
printf 'Started '; date -u
# All paths are fresh; never reset, clean or alter an existing source/output.
test ! -e "$base" && test ! -e "$art"
test "$(git -C "$old" rev-parse HEAD)" = efbdbfa3e216b0c300d381c340b0a22b24e15c13
mkdir "$base"
git clone --quiet --no-local --no-hardlinks "$old" "$src"
test ! -e "$src/.git/objects/info/alternates"
test -z "$(git -C "$src" status --porcelain --untracked-files=all)"
mkdir "$art"
printf '%s\n' 'DIAGNOSTIC ONLY. Explicit raw socket UID/appId plus lookup appId and leased barrier; preserved reviewed prerequisites. NOT FLASHABLE. No TOP/prebuilt/device changes; whole policy, networking, module ABI and runtime remain unvalidated.' >"$art/NOT_READY_FOR_FLASHING.txt"
python3 "$integration/tools/audit-kernel-tree.py" "$old" "$art/protected-before.json"
# Capture the entire actual four-file input/touch prerequisite, not a subset.
python3 - "$old" "$art/baseline-touch-complete.patch" <<'PY'
from pathlib import Path
import subprocess,sys
old,target=sys.argv[1:]
expected={'drivers/input/input.c','include/linux/input.h',
 'drivers/input/touchscreen/stm_fts1ba90a/fts_sec.c',
 'drivers/input/touchscreen/stm_fts1ba90a/fts_ts.c'}
actual=set(subprocess.check_output(['git','-C',old,'diff','--name-only'],text=True).splitlines())
assert actual==expected,(actual,expected)
p=Path(target);assert not p.exists();p.write_bytes(subprocess.check_output(['git','-C',old,'diff','--binary']))
PY
git -C "$src" apply --check "$art/baseline-touch-complete.patch"
git -C "$src" apply "$art/baseline-touch-complete.patch"
for file in drivers/input/input.c include/linux/input.h \
    drivers/input/touchscreen/stm_fts1ba90a/fts_sec.c \
    drivers/input/touchscreen/stm_fts1ba90a/fts_ts.c; do
    cmp "$src/$file" "$old/$file"
done
# Apply only checksum-locked, exact-base-verified kernel portions. Netd is NOT
# built/applied here. No arbitrary staged working file is copied into this clone.
python3 - "$src" "$integration" "$art" <<'PY'
from pathlib import Path
import hashlib,json,subprocess,sys
src,integration,art=map(Path,sys.argv[1:])
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
provenance=[]
for name in ['qtaguid-persistent-20261022-02','kernel-policy-reader-20261023-01','kernel-functionfs-20261023-01']:
 e=integration/'experiments'/name;lock=e/'staging-lock.json';r=json.loads(lock.read_text())
 projects=[p for p in r['projects'] if p['path']=='kernel/samsung/gta3xlwifi'];assert len(projects)==1
 p=projects[0];assert p['revision']=='669b9584e678ce5865ed38e04c24639082d78de1'
 assert Path(p['patch']).name==p['patch'];patch=e/p['patch'];assert sha(patch)==p['sha256']
 for f in p['files']:
  path=src/f['path'];assert path.resolve().is_relative_to(src.resolve())
  if f['reference_sha256'] is None:assert not path.exists()
  else:assert sha(path)==f['reference_sha256'],f['path']
 subprocess.run(['git','-C',str(src),'apply','--check',str(patch)],check=True)
 subprocess.run(['git','-C',str(src),'apply',str(patch)],check=True)
 for f in p['files']:assert sha(src/f['path'])==f['staged_sha256'],f['path']
 provenance.append({'experiment':name,'lock_sha256':sha(lock),'project':p})
(art/'patch-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
PY
# Exact additional netlink/mmap candidates; capability9 guard remains enabled.
python3 - "$src" "$integration" "$art" <<'PYLOCK'
from pathlib import Path
import hashlib,json,subprocess,sys
src,integration,art=map(Path,sys.argv[1:]);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
provenance=[]
for name in ['kernel-netlink-20261101-01','kernel-mmap-20261103-01','kernel-xperm-generation-20261103-01','kernel-netlink-snapshot-20261103-01','kernel-extsock-20261103-01','kernel-prlimit-20261103-01','kernel-notify-20261104-01','kernel-perf-20261104-01','kernel-firmware-20261104-01','kernel-capabilities-20261104-01','kernel-gator-20261105-01','kernel-netpolicy-20261106-01','kernel-appid-20261106-01','kernel-raw-uid-20261106-01','kernel-owner-skip-20261106-01','kernel-non-loopback-20261106-01','kernel-non-loopback-route-20261106-01','kernel-socket-creator-20261106-01','kernel-socket-creator-read-20261106-01','kernel-socket-peer-20261106-01','kernel-uid-permissions-20261107-01']:
 e=integration/'experiments'/name;lock=e/'staging-lock.json';r=json.loads(lock.read_text())
 if name in ['kernel-capabilities-20261104-01','kernel-gator-20261105-01','kernel-netpolicy-20261106-01','kernel-appid-20261106-01','kernel-raw-uid-20261106-01','kernel-owner-skip-20261106-01','kernel-non-loopback-20261106-01','kernel-non-loopback-route-20261106-01','kernel-socket-creator-20261106-01','kernel-socket-creator-read-20261106-01','kernel-socket-peer-20261106-01','kernel-uid-permissions-20261107-01']:
  assert r['supported_runtime_capability_bits']==[0,1,2,3,5,9,12] and r['unknown_active_capabilities_rejected'] is True
 else:assert r['policycap9_load_rejection_retained'] is True
 patch=e/'kernel_samsung_gta3xlwifi.patch';assert sha(patch)==r['patch_sha256']
 for f in r['files']:
  path=src/f['path']
  if f['before_sha256'] is None:assert not path.exists()
  else:assert sha(path)==f['before_sha256'],f['path']
 subprocess.run(['git','-C',str(src),'apply','--check',str(patch)],check=True)
 subprocess.run(['git','-C',str(src),'apply',str(patch)],check=True)
 for f in r['files']:assert sha(src/f['path'])==f['candidate_sha256'],f['path']
 provenance.append({'experiment':name,'lock_sha256':sha(lock),'data':r})
(art/'additional-patch-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
PYLOCK
git -C "$src" add -N -- include/uapi/linux/netfilter/xt_qtaguid_sock.h include/uapi/linux/netfilter/gta3xlwifi_netpolicy.h net/netfilter/gta3xlwifi_netpolicy.c include/uapi/linux/netfilter/gta3xlwifi_appid.h include/uapi/linux/netfilter/gta3xlwifi_socket_uid.h include/uapi/linux/netfilter/gta3xlwifi_owner_skip.h net/netfilter/gta3xlwifi_owner_skip.c include/net/gta3xlwifi_socket_peer.h net/netfilter/gta3xlwifi_socket_peer.c include/uapi/linux/netfilter/gta3xlwifi_uid_permissions.h include/net/gta3xlwifi_uid_permissions.h net/netfilter/gta3xlwifi_uid_permissions.c
python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-before.json"
python3 "$integration/tools/test-kernel-netpolicy-lease24.py" --source "$src" --output "$art/netpolicy-host"
python3 "$integration/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$integration/snapshots/port-20261106-04" "$art/android-source-before.json"
python3 "$integration/tools/test-kernel-appid-overflow24.py" --source "$src" --android-source /srv/android/src/lineage-24.0-arm64 --output "$art/appid-host"
python3 "$integration/tools/test-kernel-raw-uid24.py" --source "$src" --android-source /srv/android/src/lineage-24.0-arm64 --output "$art/raw-uid-host"
python3 "$integration/tools/test-kernel-non-loopback-route24.py" --source "$src" --android-source /srv/android/src/lineage-24.0-arm64 --output "$art/non-loopback-route-host"
python3 "$integration/tools/test-kernel-socket-creator24.py" --source "$src" --reference-kernel "$ports/kernel-non-loopback-route-20261106-01/src" --android-source /srv/android/src/lineage-24.0-arm64 --output "$art/creator-host"
python3 "$integration/tools/test-kernel-socket-creator-read24.py" --source "$src" --reference-kernel "$ports/kernel-socket-creator-20261106-01/src" --android-source /srv/android/src/lineage-24.0-arm64 --output "$art/creator-read-host"
python3 "$integration/tools/test-kernel-socket-peer24.py" --source "$src" --reference-kernel "$ports/kernel-socket-creator-read-20261106-01/src" --output "$art/peer-host"
python3 "$integration/tools/test-kernel-uid-permissions24.py" --source "$src" --android-source /srv/android/src/lineage-24.0-arm64 --output "$art/uid-permissions-host"
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
sha256sum "$out/init/uh.elf" "$out/firmware/exynos7885_acpm_fvp.fw" "$out/.config" >"$art/firmware-config.sha256"
git -C "$src" diff --binary >"$art/tracked-source.patch"
cp "$src/include/uapi/linux/netfilter/xt_qtaguid_sock.h" "$art/xt_qtaguid_sock.h"
make -C "$src" O="$out" olddefconfig
make -C "$src" O="$out" silentoldconfig
cmp /srv/android/artifacts/kernel-dt2w/kernel.config "$out/.config"
make -C "$src" O="$out" -j12 Image
"${CROSS_COMPILE}nm" "$out/vmlinux" | rg 'gta3xlwifi_appid|gta3xlwifi_raw|gta3xlwifi_owner_skip|gta3xlwifi_non_loopback|gta3xlwifi_socket_creator|gta3xlwifi_socket_peer|gta3xlwifi_uid_|gta3xlwifi_netpolicy_held|__initcall_qtaguid_mt_init' >"$art/appid-symbols.txt"
rg -q '__initcall_gta3xlwifi_appid_init' "$art/appid-symbols.txt"
rg -q '__initcall_gta3xlwifi_raw_uid_init' "$art/appid-symbols.txt"
rg -q '__initcall_qtaguid_mt_init' "$art/appid-symbols.txt"
rg -q '__initcall_gta3xlwifi_owner_skip_init' "$art/appid-symbols.txt"
rg -q ' T gta3xlwifi_socket_peer_uid$' "$art/appid-symbols.txt"
rg -q ' T gta3xlwifi_socket_creator_uid$' "$art/appid-symbols.txt"
rg -q ' T gta3xlwifi_socket_creator_init$' "$art/appid-symbols.txt"
rg -q ' T gta3xlwifi_uid_inet_create_check$' "$art/appid-symbols.txt"
rg -q ' T gta3xlwifi_uid_permissions_ioctl$' "$art/appid-symbols.txt"
rg -q ' T gta3xlwifi_netpolicy_held$' "$art/appid-symbols.txt"
cp "$out/Module.symvers" "$art/vmlinux-Module.symvers-before"
cp "$out/.config" "$art/kernel.config-before"
sha256sum "$out/arch/arm64/boot/Image" >"$art/Image-before.sha256"
rg -q '^# CONFIG_MODULE_SIG is not set$' "$out/.config"
make -C "$src" O="$out" -j12 modules
make -C "$src" O="$out" -j12 drivers/gator/gator.ko
cmp "$art/kernel.config-before" "$out/.config"
sha256sum -c "$art/Image-before.sha256"
python3 "$integration/experiments/kernel-gator-20261105-01/check-module-versions.py" "$base" "$art" "$art/module-versions.json"
cmp "$src/include/uapi/linux/netfilter/xt_qtaguid_sock.h" "$art/xt_qtaguid_sock.h"
python3 "$integration/tools/audit-kernel-tree.py" "$src" "$art/source-after.json"
python3 "$integration/tools/audit-kernel-tree.py" "$old" "$art/protected-after.json"
python3 - "$art" <<'PYAUDIT'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
for prefix in ['source','protected']:
 a=json.loads((p/(prefix+'-before.json')).read_text());b=json.loads((p/(prefix+'-after.json')).read_text())
 for key in ['revision','tree','tracked_sha256','diff_sha256']:
  assert a[key]==b[key],(prefix,key)
print('PASS: full kernel tracked-source audits; protected inputs unchanged')
PYAUDIT
cp "$out/arch/arm64/boot/Image" "$art/Image"
cp "$out/.config" "$art/kernel.config"
sha256sum "$art/Image" "$art/kernel.config" >"$art/SHA256SUMS"
python3 "$integration/tools/audit-port.py" /srv/android/src/lineage-24.0-arm64 "$integration/snapshots/port-20261106-04" "$art/android-source-after.json"
printf 'Finished '; date -u
