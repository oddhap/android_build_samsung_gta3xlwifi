#!/system/bin/sh
# Exercise detached status-bar listeners with a reversible configuration change.
set -eu
test "$(wm density | grep -c 'Override density')" = 0
test "$(settings get secure icon_blacklist)" = null
trap 'wm density reset; settings delete secure icon_blacklist' EXIT HUP INT TERM
input keyevent KEYCODE_WAKEUP
wm dismiss-keyguard
input keyevent KEYCODE_HOME
date -u
pm path com.android.systemui
pidof com.android.systemui
for cycle in 1 2 3 4; do
    wm density 241
    sleep 1
    settings put secure icon_blacklist clock
    sleep 1
    settings delete secure icon_blacklist
    sleep 1
    wm density reset
    sleep 1
done
pidof com.android.systemui
logcat -b crash -d -v threadtime
