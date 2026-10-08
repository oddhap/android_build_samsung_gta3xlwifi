#!/system/bin/sh
# Restore only the reviewed CWA1 vendor image from downloaded stock firmware.
set -eu
image=${1:?Usage: sh RESTORE_STOCK_VENDOR.sh /path/to/vendor-stock-T510XXU5CWA1.raw.img}
block=/dev/block/platform/13500000.dwmmc0/by-name/vendor
expected=9c2c323343118f8a75d31c69c367e77144b6c74c660ca9930076ecc513b8d97c
[ "$(id -u)" = 0 ] || { echo 'Root recovery shell required' >&2; exit 1; }
[ "$(getprop ro.product.device)" = gta3xlwifi ] || { echo 'Wrong device' >&2; exit 1; }
[ "$(getprop ro.twrp.version)" = 3.7.1_12 ] || { echo 'Use the supplied TWRP' >&2; exit 1; }
[ -f "$image" ] && [ ! -L "$image" ] || { echo 'Regular input image required' >&2; exit 1; }
[ "$(stat -c %s "$image")" = 343932928 ] || { echo 'Wrong input size' >&2; exit 1; }
[ "$(sha256sum "$image" | cut -d ' ' -f 1)" = "$expected" ] || { echo 'Input checksum mismatch' >&2; exit 1; }
[ -b "$block" ] && [ "$(blockdev --getsize64 "$block")" = 343932928 ] || { echo 'Wrong vendor partition' >&2; exit 1; }
for service in keystore2 recovery-keymaster recovery-gatekeeper recovery-mobicore recovery-crypto-props; do
    setprop ctl.stop "$service"
done
attempt=0
crypto_running() {
    for service in keystore2 recovery-keymaster recovery-gatekeeper recovery-mobicore recovery-crypto-props; do
        state=$(getprop "init.svc.$service")
        case "$state" in stopped|'') ;; *) return 0 ;; esac
    done
    return 1
}
while crypto_running; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 50 ] || { echo 'Recovery crypto services did not stop' >&2; exit 1; }
    sleep 0.1
done
mounted() { awk '$2 == "/vendor" || $2 ~ /^\/vendor\// { found=1 } END { exit !found }' /proc/mounts; }
if mounted; then umount /vendor; fi
if mounted; then echo 'Vendor is still mounted; refusing write' >&2; exit 1; fi
dd if="$image" of="$block" bs=1048576 conv=fsync
[ "$(sha256sum "$block" | cut -d ' ' -f 1)" = "$expected" ] || { echo 'Vendor readback failed; do not boot Android' >&2; exit 1; }
echo 'Stock vendor restored and full partition verified. Install the original ARM32 ROM before booting Android.'
