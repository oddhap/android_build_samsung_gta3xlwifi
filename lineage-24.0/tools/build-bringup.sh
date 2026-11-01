#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Targeted source compilation only. No OTA, signing or device access.
set -eo pipefail
port=/srv/android/ports/lineage-24.0-arm64
logs=/srv/android/logs/lineage-24.0-arm64
artifacts=/srv/android/artifacts/lineage-24.0-arm64
snapshot="$port/lineage-24.0/snapshots/port-20261101-02"
label=${1:?Usage: build-bringup.sh NEW_LABEL [MODULE ...]}
shift
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
exec 9>"$logs/build.lock"
flock -n 9 || { echo 'Another build/validation is active.' >&2; exit 1; }
[[ ! -e $logs/$label.exit && ! -e $artifacts/$label ]] || { echo 'Label already used; choose a fresh label.' >&2; exit 1; }
mkdir "$artifacts/$label"
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; date -u +%FT%TZ > "$artifacts/$label/finished-at.txt"; exit "$rc"' EXIT
source "$port/env.sh"
[[ $PWD == /srv/android/src/lineage-24.0-arm64 ]] || exit 1
python3 "$port/lineage-24.0/tools/audit-port.py" "$PWD" "$snapshot" "$artifacts/$label/source-audit-before.json"
python3 - "$PWD" "$artifacts/$label" <<'PY'
import hashlib,json,sys
from pathlib import Path
top,out=map(Path,sys.argv[1:])
expected={'Image':'33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553','dtbo.img':'b9041c37713a745290d9a0203423436b6caa7a1307ced79b6963b4f1f0271c4b','vendor.img':'a847a527931d61e5702b8a025210c84eb88a37ef1e60df93b6393a16dae9183a'}
for name,sha in expected.items():
 h=hashlib.sha256()
 with (top/'device/samsung/gta3xlwifi/prebuilt'/name).open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 if h.hexdigest()!=sha:raise SystemExit('Binary input changed: '+name)
(out/'binary-inputs.json').write_text(json.dumps(expected,indent=2)+'\n')
PY
mkdir -p "$CCACHE_DIR"
source build/envsetup.sh
lunch lineage_gta3xlwifi aosp_current userdebug
if (( $# == 0 )); then
 set -- 'libaudiohal@4.0' com.android.vndk.v30 gta3xlwifi_recovery_header_sync \
  selinux_policy libprocessgroup libprocessgroup_setup libfs_mgr libmeminfo gpuservice \
  libc linker linkerconfig
fi
printf '%s\n' "$@" > "$artifacts/$label/targets.txt"
date -u +%FT%TZ > "$artifacts/$label/started-at.txt"
m -j16 "$@"
python3 "$port/lineage-24.0/tools/audit-port.py" "$PWD" "$snapshot" "$artifacts/$label/source-audit-after.json"
