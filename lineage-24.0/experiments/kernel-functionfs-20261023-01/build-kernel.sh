#!/usr/bin/env bash
# Isolated diagnostic build only. Does NOT update TOP/prebuilt or any device.
set -euo pipefail
ports=/srv/android/ports/lineage-23.2-arm64
integration=$ports/lineage-23.2
base=$ports/kernel-functionfs-20261023-01
src=$base/src
out=$base/out
old=/srv/android/src/kernel-gta3xlwifi-dt2w
label=kernel-functionfs-build-20261023-01
art=/srv/android/artifacts/lineage-23.2-arm64/$label
logs=/srv/android/logs/lineage-23.2-arm64
exec 9>"$logs/build.lock"
flock -n 9 || { echo 'Another build/audit holds build.lock'; exit 75; }
exec >"$logs/$label.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" >"$logs/$label.exit"; date -u; exit "$result"' EXIT
printf 'Started '; date -u
# All paths are fresh; never reset, clean or alter an existing source/output.
test ! -e "$base" && test ! -e "$art"
test "$(git -C "$old" rev-parse HEAD)" = efbdbfa3e216b0c300d381c340b0a22b24e15c13
mkdir "$base"
git clone --quiet --no-local --no-hardlinks "$old" "$src"
test ! -e "$src/.git/objects/info/alternates"
test -z "$(git -C "$src" status --porcelain --untracked-files=all)"
mkdir "$art"
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
python3 "$integration/tools/test-kernel-functionfs.py" "$src" \
    "$ports/functionfs23/kernel/samsung/gta3xlwifi" "$ports/upstream-android16-6.12"
python3 "$integration/tools/test-kernel-nnp-transition.py" "$src" "$old" "$ports/upstream-android16-6.12" \
    --mount-reference "$ports/nnp-upstream-mount"
python3 "$integration/tools/test-policy-xperm-cap.py" "$src/security/selinux/ss/policydb.c"
python3 "$integration/tools/check-kernel-policy-xperms.py" \
    --inspector /srv/android/artifacts/lineage-23.2-arm64/policy-kernel-format-20261023-02/inspect-policy-xperms \
    "$src" \
    /srv/android/artifacts/lineage-23.2-arm64/vendor-validation-20261020/policy-user-20261023-01/init-runtime-diagnostic.policy \
    "$art/reader-record-check"
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
cp "$out/arch/arm64/boot/Image" "$art/Image"
cp "$out/.config" "$art/kernel.config"
sha256sum "$art/Image" "$art/kernel.config" >"$art/SHA256SUMS"
printf '%s\n' 'DIAGNOSTIC KERNEL ONLY. FunctionFS labels plus NNP/namespace support; NOT USB, whole-policy, AVC, exec, reload-concurrency or flash approval. Strictly USER_NS=n. No TOP/prebuilt/device changes.' >"$art/NOT_READY_FOR_FLASHING.txt"
printf 'Finished '; date -u
