#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep the recovery resetprop library variant and its copy ordering intact."""
from pathlib import Path
import argparse
p=argparse.ArgumentParser();p.add_argument('checkout',type=Path);a=p.parse_args()
f=a.checkout/'bootable/recovery/prebuilt/Android.mk';s=f.read_text();old='$(TARGET_OUT_SHARED_LIBRARIES)/libresetprop.so';new='$(TARGET_RECOVERY_ROOT_OUT)/system/$(notdir $(TARGET_OUT_SHARED_LIBRARIES))/libresetprop.so'
assert s.count(old)==1 or (s.count(old)==0 and s.count(new)==1)
f.write_text(s.replace(old,new))
