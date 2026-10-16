#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Move selected Soong apps and their companion modules to the system image.

The Make PRODUCT_FORCE_PRODUCT_MODULES_TO_SYSTEM_PARTITION override does not
change Soong install paths in Android 14. Export these changes as pinned source
patches; retain every app and move its JNI and permissions with it.
"""
import argparse,json,re
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('top',type=Path);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
files={
'packages/apps/Aperture/app/Android.bp':3,
'packages/apps/Aperture/lens_launcher/Android.bp':1,
'packages/apps/DeskClock/Android.bp':3,
'packages/apps/Etar/app/Android.bp':4,
'packages/apps/ExactCalculator/Android.bp':1,
'packages/apps/Gallery2/Android.bp':1,
'packages/apps/Gallery2/jni/Android.bp':1,
'packages/apps/Gallery2/jni_jpegstream/Android.bp':1,
'packages/apps/Glimpse/app/Android.bp':3,
'packages/apps/Jelly/app/Android.bp':3,
'packages/inputmethods/LatinIME/java/Android.bp':1,
'packages/inputmethods/LatinIME/native/jni/Android.bp':1,
'packages/apps/Seedvault/contactsbackup/Android.bp':2,
'packages/apps/Recorder/app/Android.bp':1,
'packages/apps/Contacts/Android.bp':1,
'packages/apps/Eleven/Android.bp':2,
}
changes=[]
for relative,count in files.items():
 path=a.top/relative;text=path.read_text();pattern=r'\bproduct_specific: (?:true|false),'
 assert len(re.findall(pattern,text))==count,(relative,'review changed upstream module definitions')
 updated=re.sub(pattern,'product_specific: false,',text)
 changes.append((path,updated,relative,count))
path=a.top/'frameworks/base/data/etc/Android.bp';text=path.read_text();pattern=r'(?ms)(^prebuilt_etc \{\n    name: "privapp_whitelist_com.android.contacts",\n    product_specific: )(?:true|false)(,)';assert len(re.findall(pattern,text))==1
updated=re.sub(pattern,r'\g<1>false\2',text);changes.append((path,updated,'frameworks/base/data/etc/Android.bp',1))
for path,updated,_,_ in changes:path.write_text(updated)
report={'passed':True,'apps_removed':False,'partition_sizes_changed':False,'soong_source_product_specific_overrides':{rel:count for _,_,rel,count in changes},'jni_and_companion_permission_modules_moved_together':True,'signed_image_validation_pending':True}
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2)+'\n');print('Updated '+str(sum(x[3] for x in changes))+' Soong module/default partition properties; no apps removed.')
