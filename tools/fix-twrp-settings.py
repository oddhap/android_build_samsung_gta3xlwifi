#!/usr/bin/env python3
"""Device-scoped settings storage and optional version suffix for TWRP."""
from pathlib import Path
root = Path('/srv/android/src/twrp-12.1/bootable/recovery')
p = root / 'Android.mk'
s = p.read_text()
old = '''ifneq ($(TW_DEVICE_VERSION),)
    LOCAL_CFLAGS += -DTW_DEVICE_VERSION='"-$(TW_DEVICE_VERSION)"'
else
    LOCAL_CFLAGS += -DTW_DEVICE_VERSION='"-0"'
endif'''
new = '''ifeq ($(TW_OMIT_DEVICE_VERSION),true)
    LOCAL_CFLAGS += -DTW_DEVICE_VERSION='""'
else
'''+old+'''
endif
ifneq ($(TW_SETTINGS_STORAGE_PATH),)
    LOCAL_CFLAGS += -DTW_SETTINGS_STORAGE_PATH='"$(TW_SETTINGS_STORAGE_PATH)"'
endif'''
if new not in s:
    assert s.count(old) == 1
    p.write_text(s.replace(old, new, 1))
p = root / 'data.cpp'
s = p.read_text()
old = '''string DataManager::GetSettingsStoragePath(void)
{
	return GetStrValue("tw_settings_path");
}'''
new = '''string DataManager::GetSettingsStoragePath(void)
{
#ifdef TW_SETTINGS_STORAGE_PATH
    // Preferences must remain writable when the device's FBE storage is locked.
    // Current storage, backups and encryption credentials use separate values.
    return TW_SETTINGS_STORAGE_PATH;
#else
	return GetStrValue("tw_settings_path");
#endif
}'''
if new not in s:
    assert s.count(old) == 1
    p.write_text(s.replace(old, new, 1))
print('Device-scoped TWRP settings and version options applied')

# Upstream hides the preference checkbox while /data is encrypted. A device
# with separate settings storage can still save preferences safely.
p = root / 'data.cpp'
s = p.read_text()
old = '\tmkdir(mkdir_path, 0777);\n'
new = old+'''#ifdef TW_SETTINGS_STORAGE_PATH
    SetValue("tw_can_persist_settings",
            PartitionManager.Is_Mounted_By_Path(GetSettingsStoragePath())
                    && access(mkdir_path, W_OK) == 0 ? 1 : 0);
#else
    SetValue("tw_can_persist_settings", is_enc == 0 ? 1 : 0);
#endif
'''
if new not in s:
    assert s.count(old) == 1
    p.write_text(s.replace(old, new, 1))
for name in ('portrait.xml', 'landscape.xml'):
    p = root / 'gui/theme/common' / name
    s = p.read_text()
    old = '''<condition var1="tw_is_encrypted" var2="0"/>
'''
    start = s.index('<page name="system_readonly">')
    end = s.index('</page>', start)
    page = s[start:end]
    new = '<condition var1="tw_can_persist_settings" var2="1"/>\n'
    if new not in page:
        assert page.count(old) == 1
        page = page.replace(old, new, 1)
        p.write_text(s[:start]+page+s[end:])

# Use the initialized folder variable and an actual directory separator.
# TW_RECOVERY_NAME is a literal name, not a populated DataManager key.
p = root / 'data.cpp'
s = p.read_text()
s = s.replace('GetStrValue(TW_RECOVERY_NAME)', 'GetStrValue(TW_RECOVERY_FOLDER_VAR)')
s = s.replace('sprintf(settings_file, "%s%s", mkdir_path, TW_SETTINGS_FILE);',
              'sprintf(settings_file, "%s/%s", mkdir_path, TW_SETTINGS_FILE);')
s = s.replace('GetStrValue(TW_RECOVERY_FOLDER_VAR) + TW_SETTINGS_FILE;',
              'GetStrValue(TW_RECOVERY_FOLDER_VAR) + "/" + TW_SETTINGS_FILE;')
old = '\tmData.SetValue(TW_RECOVERY_FOLDER_VAR, TW_DEFAULT_RECOVERY_FOLDER);\n'
new = old+'''#ifdef TW_SETTINGS_STORAGE_PATH
    mData.SetValue("tw_settings_path", TW_SETTINGS_STORAGE_PATH);
#endif
'''
if new not in s:
    assert s.count(old) == 1
    s = s.replace(old, new, 1)
p.write_text(s)
