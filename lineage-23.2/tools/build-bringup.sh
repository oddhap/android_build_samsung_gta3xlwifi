#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Targeted compile only. Does not sign, package an OTA, or touch a device.
set -eo pipefail
port=/srv/android/ports/lineage-23.2-arm64
logs=/srv/android/logs/lineage-23.2-arm64
label=${1:?Usage: build-bringup.sh LABEL [MODULE ...]}
shift
[[ $label =~ ^[a-zA-Z0-9_-]+$ ]] || exit 2
mkdir -p "$logs"
exec 9>"$logs/build.lock"
flock -n 9 || { echo 'Another 23.2 build is running.' >&2; exit 1; }
trap 'rc=$?; printf "%s\n" "$rc" > "$logs/$label.exit"; exit "$rc"' EXIT
printf '[%s] Starting %s\n' "$(date -u +%FT%TZ)" "$label"
source "$port/env.sh"
[[ $PWD == /srv/android/src/lineage-23.2-arm64 ]] || exit 1
# nsjail bind-mounts CCACHE_DIR even during product configuration. An absent
# bind source can become a regular placeholder file; create it before lunch.
[[ ! -L $CCACHE_DIR ]] || { echo 'Refusing a symlinked compiler cache.' >&2; exit 1; }
mkdir -p "$CCACHE_DIR"
source build/envsetup.sh
# build/release/release_config_map.textproto maps aosp_current to bp4a.
lunch lineage_gta3xlwifi bp4a userdebug
if (( $# == 0 )); then
    set -- 'libaudiohal@4.0' com.android.vndk.v30 gta3xlwifi_recovery_header_sync \
        selinux_policy libprocessgroup libprocessgroup_setup libfs_mgr libmeminfo gpuservice
fi
printf 'Compile targets: %s\n' "$*"
m -j16 "$@"
printf '[%s] Finished %s\n' "$(date -u +%FT%TZ)" "$label"
