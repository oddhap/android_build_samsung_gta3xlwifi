#!/usr/bin/env python3
"""Keep real user/group quotas without unsupported ext4 project quotas."""
from pathlib import Path

path = Path('/srv/android/src/lineage-21.0/system/core/fs_mgr/fs_mgr.cpp')
before = '''    // Enable projid support by default
    bool want_projid = true;'''
after = '''    // SM-T510's Samsung kernel supports user/group quotas but not the ext4
    // project feature. Enabling it makes /data unmountable on the next boot.
    // Other devices keep Android 14's default project-quota behavior.
    bool want_projid = GetBoolProperty("ro.gta3xlwifi.ext4_project_quota", true);'''
data = path.read_text()
if after not in data:
    if data.count(before) != 1:
        raise SystemExit('Unexpected Android 14 quota source anchor')
    path.write_text(data.replace(before, after, 1))
print('Applied device-scoped ext4 quota capability selection')
