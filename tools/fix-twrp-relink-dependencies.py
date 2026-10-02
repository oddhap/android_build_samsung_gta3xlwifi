#!/usr/bin/env python3
"""Make TWRP's library copy rerun when our runtime libraries change."""
from pathlib import Path

path = Path('/srv/android/src/twrp-12.1/bootable/recovery/prebuilt/Android.mk')
text = path.read_text()
anchor = 'LOCAL_MODULE := relink_libraries\n'
addition = ('# SM-T510: required modules enforce ordering but not copy freshness.\n'
            'LOCAL_ADDITIONAL_DEPENDENCIES += $(TARGET_OUT_SHARED_LIBRARIES)/libminuitwrp.so $(TARGET_OUT_SHARED_LIBRARIES)/libresetprop.so $(TARGET_OUT_SHARED_LIBRARIES)/libfscrypttwrp.so\n')
previous = addition.replace(' $(TARGET_OUT_SHARED_LIBRARIES)/libfscrypttwrp.so', '')
text = text.replace(previous, addition)
assert text.count(anchor) == 1
if addition not in text:
    path.write_text(text.replace(anchor, anchor + addition))
else:
    path.write_text(text)
