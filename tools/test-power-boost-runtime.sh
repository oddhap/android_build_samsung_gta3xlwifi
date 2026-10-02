#!/system/bin/sh
# Run as rooted adb on the verified new SM-T510 build. Restores battery saver/logging.
set -eu
GPU=/sys/devices/platform/11500000.mali/gta3xlwifi_min_lock
LITTLE=/dev/gta3xlwifi_cluster0_min
BIG=/dev/gta3xlwifi_cluster1_min
[ "$(getprop ro.product.model)" = SM-T510 ]
[ "$(getenforce)" = Enforcing ]
[ -e "$GPU" ] && [ -e "$LITTLE" ] && [ -e "$BIG" ]
dumpsys battery | grep -q 'UPDATES STOPPED' && { echo 'FAIL: battery service already overridden'; exit 1; }
old_saver=$(settings get global low_power)
old_log=$(getprop debug.gta3xlwifi.power_log)
cleanup() {
    cmd battery reset
    case "$old_saver" in 1) cmd power set-mode 1;; *) cmd power set-mode 0;; esac
    setprop debug.gta3xlwifi.power_log "$old_log"
    input keyevent KEYCODE_WAKEUP
}
trap cleanup EXIT HUP INT TERM
sample() {
    printf '%s: uptime=' "$1"
    cut -d ' ' -f 1 /proc/uptime
    printf 'framework GPU floor='; cat "$GPU"
    printf 'Samsung touch/LCD controls='; cat /sys/class/sec/tsp/input/enabled /sys/class/power_supply/battery/lcd
    printf 'aggregate little/big QoS='; od -An -td4 -N4 "$LITTLE"; od -An -td4 -N4 "$BIG"
}
expect_gpu() {
    actual=$(cat "$GPU")
    [ "$actual" = "$1" ] || { echo "FAIL GPU floor: expected $1 got $actual"; exit 1; }
}
# USB charging prevents Android from enabling saver. Simulate unplug only for
# this test and restore the real battery service state in the cleanup trap.
expect_cpu_idle() {
    value=$(od -An -td4 -N4 "$LITTLE" | tr -d '[:space:]')
    [ "$value" = "$baseline_little" ] || { echo "FAIL: little QoS $value != baseline $baseline_little"; exit 1; }
    value=$(od -An -td4 -N4 "$BIG" | tr -d '[:space:]')
    [ "$value" = "$baseline_big" ] || { echo "FAIL: big QoS $value != baseline $baseline_big"; exit 1; }
}
setprop debug.gta3xlwifi.power_log 1
cmd power set-mode 0
input keyevent KEYCODE_WAKEUP
wm dismiss-keyguard
input keyevent KEYCODE_HOME
sleep 3
sample idle_before
expect_gpu 0
# QoS reads the aggregate, including the cpufreq driver's hardware minimum.
baseline_little=$(od -An -td4 -N4 "$LITTLE" | tr -d '[:space:]')
baseline_big=$(od -An -td4 -N4 "$BIG" | tr -d '[:space:]')
# Continuous injected input exercises the actual InputDispatcher/PowerManager path.
input swipe 600 1700 600 350 1200 &
gesture_pid=$!
sleep .25
sample during_touch
expect_gpu 545000
value=$(od -An -td4 -N4 "$LITTLE" | tr -d '[:space:]')
[ "$value" -ge 1248000 ] || { echo "FAIL: touch little QoS $value"; exit 1; }
value=$(od -An -td4 -N4 "$BIG" | tr -d '[:space:]')
[ "$value" -ge 1352000 ] || { echo "FAIL: touch big QoS $value"; exit 1; }
wait "$gesture_pid"
sleep 3
sample touch_expired
expect_gpu 0
expect_cpu_idle
# App start uses ActivityTaskManager's launch mode; inspect native logs for the peak.
am start -W -a android.settings.SETTINGS >/dev/null
sleep 3
sample launch_expired
expect_gpu 0
expect_cpu_idle
input keyevent KEYCODE_HOME
sleep 3
input swipe 600 1700 600 350 1200 &
gesture_pid=$!
sleep .25
input keyevent KEYCODE_SLEEP
sleep .2
sample screen_off
expect_gpu 0
wait "$gesture_pid"
dumpsys power | grep -E 'mWakefulness=|mHalInteractiveModeEnabled=' || true
input keyevent KEYCODE_WAKEUP
wm dismiss-keyguard
sleep 3
sample after_wake
expect_gpu 0
expect_cpu_idle
cmd battery unplug
cmd battery set level 80
cmd power set-mode 1
sleep 1
[ "$(settings get global low_power)" = 1 ] || { echo 'FAIL: battery saver did not enable'; exit 1; }
input swipe 600 1700 600 350 1000 &
gesture_pid=$!
sleep .25
sample saver_touch
expect_gpu 0
wait "$gesture_pid"
am start -W -a android.settings.SETTINGS >/dev/null
sleep 1
sample saver_launch
expect_gpu 0
cmd power set-mode 0
input keyevent KEYCODE_HOME
sleep 3
sample saver_disabled_idle
expect_gpu 0
expect_cpu_idle
logcat -d -s Gta3xlwifiPower:I '*:S'
echo 'PASS: live touch boost, expiry, screen-off, wake and battery saver'
