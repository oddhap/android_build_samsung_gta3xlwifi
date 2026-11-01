#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fresh production POLICY ONLY build. No source edits, ROM, signing or device I/O.
set -eo pipefail
port=/srv/android/ports/lineage-23.2-arm64
logs=/srv/android/logs/lineage-23.2-arm64
label=policy-user-20261023-01
mkdir -p "$logs"
exec 9>"$logs/build.lock"
flock -n 9 || { echo 'Another 23.2 build/audit is running.' >&2; exit 1; }
[[ ! -e "$logs/$label.exit" ]] || { echo 'Refusing to overwrite previous result.' >&2; exit 1; }
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
source "$port/env.sh"
[[ $PWD == /srv/android/src/lineage-23.2-arm64 ]] || exit 1
export OUT_DIR=out-policy-user-20261023-01
export CCACHE_DIR=/srv/android/ccache-lineage-23.2-policy-user
[[ ! -e $OUT_DIR && ! -L $OUT_DIR ]] || { echo 'Refusing existing output.' >&2; exit 1; }
[[ ! -L $CCACHE_DIR ]] || exit 1
mkdir -p "$CCACHE_DIR"
[[ -d $CCACHE_DIR ]] || exit 1
python3 "$port/lineage-23.2/tools/audit-port.py" "$PWD" \
  "$port/lineage-23.2/snapshots/bringup-20261021-06" \
  "$logs/$label.before-source-audit.json"
source build/envsetup.sh
lunch lineage_gta3xlwifi bp4a user
[[ $(get_build_var TARGET_BUILD_VARIANT) == user ]] || exit 1
[[ $(get_build_var OUT_DIR) == "$OUT_DIR" ]] || exit 1
get_build_var TARGET_BUILD_VARIANT > "$logs/$label.variant"
get_build_var PRODUCT_OUT > "$logs/$label.product-out"
printf '[%s] Production POLICY ONLY: %s\n' "$(date -u +%FT%TZ)" "$OUT_DIR"
m -j16 selinux_policy
printf '[%s] Finished production policy build\n' "$(date -u +%FT%TZ)"
