#!/usr/bin/env python3
"""Stage an optional, uninstalled packet probe; never included in ROM packages."""
from pathlib import Path
import shutil
port=Path('/srv/android/ports/lineage-21')
test=Path('/srv/android/src/lineage-21.0/device/samsung/gta3xlwifi/network-probe')
test.mkdir(exist_ok=True)
shutil.copy2(port/'tests/packet-probe.Android.bp',test/'Android.bp')
shutil.copy2(port/'tests/packet-probe.cpp',test/'packet-probe.cpp')
for p in (port/'compat/netd').iterdir(): shutil.copy2(p,test/p.name)
shutil.copytree(port/'tests/include',test/'include',dirs_exist_ok=True)
