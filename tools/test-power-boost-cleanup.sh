#!/system/bin/sh
# Rooted development-device check: one deliberate system_server restart.
set -eu
GPU=/sys/devices/platform/11500000.mali/gta3xlwifi_min_lock
CPU=/dev/gta3xlwifi_cluster0_min
[ "$(getprop ro.product.model)" = SM-T510 ]
[ "$(getenforce)" = Enforcing ]
old_saver=$(settings get global low_power)
gpu_diagnostic_pending=0
fixture=/data/local/tmp/gta3xlwifi-qos-test.bin
cleanup() {
    if [ "$gpu_diagnostic_pending" = 1 ]; then echo 0 > "$GPU"; fi
    rm -f "$fixture"
    cmd battery reset
    case "$old_saver" in 1) cmd power set-mode 1;; *) cmd power set-mode 0;; esac
}
trap cleanup EXIT HUP INT TERM
# Keep ordinary touch requests quiescent while testing independent fd cleanup.
# Fake unplug is necessary because Android disallows battery saver while charging.
cmd battery unplug
cmd battery set level 80
sleep 1
cmd power set-mode 1
sleep 2
[ "$(settings get global low_power)" = 1 ] || { echo "FAIL: diagnostic battery saver did not enable"; exit 1; }
[ "$(cat "$GPU")" = 0 ] || { echo 'FAIL: boost already active'; exit 1; }
base=$(od -An -td4 -N4 "$CPU" | tr -d '[:space:]')
# An independent userspace CPU request must disappear when its fd closes.
exec 3>"$CPU"
# Force one four-byte write; PM QoS accepts a native-endian int32.
printf '\000\013\023\000' > "$fixture"
[ "$(stat -c %s "$fixture")" = 4 ]
dd if="$fixture" bs=4 count=1 >&3
value=$(od -An -td4 -N4 "$CPU" | tr -d '[:space:]')
echo "CPU request active: $value kHz"
[ "$value" -ge 1248000 ]
exec 3>&-
value=$(od -An -td4 -N4 "$CPU" | tr -d '[:space:]')
echo "CPU after fd close: $value kHz (baseline $base)"
[ "$value" = "$base" ]
old_pid=$(pidof system_server)
# A diagnostic floor tests the init cleanup independently of the helper's timer.
gpu_diagnostic_pending=1
echo 676000 > "$GPU"
[ "$(cat "$GPU")" = 676000 ]
kill -KILL "$old_pid"
released_before_server=0
for sample in $(seq 1 60); do
    floor=$(cat "$GPU")
    current_pid=$(pidof system_server || true)
    if [ "$floor" = 0 ] && [ -z "$current_pid" ]; then
        released_before_server=1
        gpu_diagnostic_pending=0
        echo 'GPU released by init before replacement system_server starts'
        break
    fi
    sleep .05
done
[ "$released_before_server" = 1 ] || { echo 'FAIL: init cleanup not observed before replacement'; exit 1; }
for sample in $(seq 1 90); do
    current_pid=$(pidof system_server || true)
    if [ -n "$current_pid" ] && [ "$current_pid" != "$old_pid" ]; then
        # Wait for the native backend to initialize in the replacement process.
        if ls -l /proc/"$current_pid"/fd 2>/dev/null | grep -q gta3xlwifi_cluster0_min; then
            echo "Replacement system_server ready: $old_pid -> $current_pid"
            sleep 3
            echo 'PASS: fd CPU cleanup and init GPU cleanup across system_server restart'
            exit 0
        fi
    fi
    sleep 1
done
echo 'FAIL: replacement system_server did not initialize in time'
exit 1
