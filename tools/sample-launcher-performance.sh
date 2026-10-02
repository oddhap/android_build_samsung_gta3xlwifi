#!/system/bin/sh
# Repeatable, read-only driver sampling during launcher drawer gestures.
set -eu
input keyevent KEYCODE_WAKEUP
wm dismiss-keyguard
input keyevent KEYCODE_HOME
sleep 1
dumpsys gfxinfo com.android.launcher3 reset >/dev/null
sample_file=/data/local/tmp/lineage-performance-samples.txt
(
    for sample in $(seq 1 60); do
        printf '%s ' "$(cut -d ' ' -f 1 /proc/uptime)"
        for node in \
            /sys/devices/platform/11500000.mali/clock \
            /sys/devices/platform/11500000.mali/utilization \
            /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq \
            /sys/devices/system/cpu/cpu6/cpufreq/scaling_cur_freq; do
            tr '\n' ' ' < "$node"
        done
        printf '\n'
        sleep .2
    done
) > "$sample_file" &
sampler_pid=$!
for gesture in $(seq 1 8); do
    input keyevent KEYCODE_HOME
    input swipe 600 1700 600 350 450
    input swipe 600 450 600 1700 450
done
wait "$sampler_pid"
printf 'GPU_KHZ GPU_UTIL CPU_LITTLE_KHZ CPU_BIG_KHZ samples\n'
cat "$sample_file"
rm "$sample_file"
dumpsys gfxinfo com.android.launcher3
dumpsys thermalservice
