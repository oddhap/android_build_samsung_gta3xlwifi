#!/usr/bin/env python3
"""Allow Wi-Fi products to disable the entire unused TeleService application."""
from pathlib import Path
root=Path('/srv/android/src/lineage-21.0/packages/services/Telephony')
p=root/'AndroidManifest.xml'
s=p.read_text()
old='<application android:name="PhoneApp"'
new=old+'\n            android:enabled="@bool/config_enable_telephony"'
if new not in s:
    assert s.count(old)==1
    p.write_text(s.replace(old,new,1))
p=root/'res/values/config.xml'
s=p.read_text()
old='<resources>'
new=old+'\n    <!-- Wi-Fi products can exclude radio services through a static overlay. -->\n    <bool name="config_enable_telephony">true</bool>'
if new not in s:
    assert s.count(old)==1
    p.write_text(s.replace(old,new,1))

# Enabled alone is insufficient: persistent system apps are started regardless
# of their user-disabled state. Gate persistence with the same product resource.
p=root/'AndroidManifest.xml'
s=p.read_text()
old='            android:persistent="true"'
new='            android:persistent="@bool/config_enable_telephony"'
if new not in s:
    assert s.count(old)==1
    p.write_text(s.replace(old,new,1))
print('TeleService application enablement and persistence resources applied')
