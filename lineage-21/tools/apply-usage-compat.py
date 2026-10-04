#!/usr/bin/env python3
"""Handle optional CPU/battery data on the legacy kernel without inventing it."""
from pathlib import Path
root = Path('/srv/android/src/lineage-21.0')
def edit(relative, before, after):
    path = root / relative
    source = path.read_text()
    if after in source:
        return
    if source.count(before) != 1:
        raise SystemExit('Unexpected source anchor: ' + relative)
    path.write_text(source.replace(before, after, 1))
reader = 'frameworks/base/core/java/com/android/internal/os/KernelSingleProcessCpuThreadReader.java'
edit(reader, 'import android.annotation.Nullable;', 'import android.annotation.Nullable;\nimport android.os.SystemProperties;')
edit(reader, '    private boolean mIsTracking;', '    private boolean mIsTracking;\n\n    private final boolean mCpuTimeInStateSupported;')
edit(reader, '        mCpuTimeInStateReader = cpuTimeInStateReader;', '''        mCpuTimeInStateReader = cpuTimeInStateReader;
        // Mock readers remain usable on any kernel; production needs eBPF.
        mCpuTimeInStateSupported = cpuTimeInStateReader != null
                || SystemProperties.getBoolean("ro.kernel.ebpf.supported", true);''')
edit(reader, '    public void startTrackingThreadCpuTimes() {', '''    public void startTrackingThreadCpuTimes() {
        if (!mCpuTimeInStateSupported) {
            return;
        }''')
edit(reader, '    public int getCpuFrequencyCount() {\n        if (mFrequencyCount == 0) {', '''    public int getCpuFrequencyCount() {
        if (!mCpuTimeInStateSupported) {
            return 0;
        }
        if (mFrequencyCount == 0) {''')
edit(reader, '    public ProcessCpuUsage getProcessCpuUsage() {', '''    public ProcessCpuUsage getProcessCpuUsage() {
        if (!mCpuTimeInStateSupported) {
            return null;
        }''')
entry = 'packages/apps/Settings/src/com/android/settings/fuelgauge/batteryusage/BatteryEntry.java'
edit(entry, '''            final UidBatteryConsumer uidBatteryConsumer, final Dimensions dimension) {
        try {''', '''            final UidBatteryConsumer uidBatteryConsumer, final Dimensions dimension) {
        // Older kernels/snapshots may have totals but no process-state columns.
        // Keep the existing unavailable-value fallback without repeatedly throwing.
        if (uidBatteryConsumer.getKey(BatteryConsumer.POWER_COMPONENT_CPU,
                dimension.processState) == null) {
            return 0.0d;
        }
        try {''')
telephony = 'frameworks/base/telephony/java/android/telephony/TelephonyManager.java'
edit(telephony, 'import android.content.Context;', 'import android.content.Context;\nimport android.content.res.Resources;')
edit(telephony, '    public int getActiveModemCount() {\n        int modemCount = 1;', """    public int getActiveModemCount() {
        // The context-free manager is used by PhoneFactory during startup.
        // Its capability methods default to true without a Context, even on
        // Wi-Fi products. Static framework resources still describe hardware.
        if (mContext == null) {
            final Resources resources = Resources.getSystem();
            if (!resources.getBoolean(com.android.internal.R.bool.config_voice_capable)
                    && !resources.getBoolean(com.android.internal.R.bool.config_sms_capable)
                    && !resources.getBoolean(com.android.internal.R.bool.config_mobile_data_capable)) {
                return 0;
            }
        }
        int modemCount = 1;""")
worker = 'frameworks/base/services/core/java/com/android/server/power/stats/BatteryExternalStatsWorker.java'
edit(worker, '            mTelephony = tm;', '''            // A TelephonyManager object also exists on Wi-Fi-only tablets.
            // Only query modem energy data when an actual modem is configured.
            mTelephony = tm != null && tm.getActiveModemCount() > 0 ? tm : null;''')
print('Applied optional CPU and battery data compatibility guards')
