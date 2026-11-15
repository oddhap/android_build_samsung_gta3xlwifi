#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify selected module build outputs, actual post-R8 DEX Binder identities and ELF ABIs.

No Android service/kernel/device execution or complete ROM validation is claimed.
"""
import argparse,fcntl,hashlib,json,re,struct,subprocess,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','snapshot','build','selection','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists();lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def bind(f):f=Path(f).resolve();inputs[str(f)]=sha(f)
log=Path('/srv/android/logs/lineage-24.0-arm64')/(a.build.name+'.log');exit_file=log.with_suffix('.exit');assert exit_file.read_text().strip()=='0';assert 'build completed successfully' in log.read_text()
for name in ['source-before.json','source-after.json']:
 f=a.build/name;r=json.loads(f.read_text());assert r['passed'] and r['project_count']==1243 and r['reviewed_patch_count']==20;assert r['manifest_sha256']==sha(a.snapshot/'port-manifest.xml');bind(f)
s=json.loads(a.selection.read_text())
for rel,v in s['files'].items():assert sha(T/rel)==v['after_sha256']
for n,h in s['prebuilts'].items():f=T/'device/samsung/gta3xlwifi/prebuilt'/n;assert sha(f)==h;bind(f)
product=T/'out/target/product/gta3xlwifi';elf=[]
for rel in ['system/bin/netd','system/bin/iptables','apex/com.android.tethering/lib64/libnetd_updatable.so','apex/com.android.tethering/lib64/libnetd_resolv.so']:
 f=product/rel;data=f.read_bytes();assert data[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',data,18)[0]==183;bind(f);elf.append({'path':rel,'ELF_bits':64,'machine':183,'sha256':sha(f)})
jar=product/'apex/com.android.tethering/javalib/service-connectivity.jar';bind(jar);strings=set();classes=set();dexes=[]
with zipfile.ZipFile(jar) as z:
 for name in z.namelist():
  if not re.fullmatch(r'classes\d*\.dex',name):continue
  data=z.read(name);assert data.startswith(b'dex\n') and struct.unpack_from('<I',data,40)[0]==0x12345678
  count,offset=struct.unpack_from('<II',data,56);words=[]
  for i in range(count):
   at=struct.unpack_from('<I',data,offset+4*i)[0]
   for _ in range(5):
    value=data[at];at+=1
    if value<128:break
   else:raise AssertionError('Invalid DEX length')
   end=data.index(0,at);words.append(data[at:end].decode('utf-8',errors='replace'))
  strings.update(words);n,at=struct.unpack_from('<II',data,64);types=[struct.unpack_from('<I',data,at+4*i)[0] for i in range(n)];n,at=struct.unpack_from('<II',data,96)
  for i in range(n):classes.add(words[types[struct.unpack_from('<I',data,at+32*i)[0]]])
  dexes.append({'name':name,'sha256':hashlib.sha256(data).hexdigest(),'class_count':n})
assert dexes
identities=[]
for name in ['IGta3xlwifiNetpolicy','IOemNetd','IOemNetdUnsolicitedEventListener']:
 desc='com.android.internal.net.'+name;present=desc in strings;class_present='L'+desc.replace('.','/')+';' in classes
 # The unsolicited listener has no consumer in this build. R8 may remove its
 # entire unused class/descriptor; it must never rename a retained interface.
 if name=='IOemNetdUnsolicitedEventListener' and not present and not class_present:
  identities.append({'interface':name,'unused_listener_removed_by_R8':True});continue
 assert present and class_present
 assert 'android.net.connectivity.'+desc not in strings
 identities.append({'interface':name,'post_R8_descriptor':desc,'original_class_retained':True})
base=T/'out/soong/.intermediates/system/netd/server/gta3xlwifi-netpolicy-aidl-java/android_common_apex31/javac/gta3xlwifi-netpolicy-aidl-java.jar';bind(base);javap=T/'prebuilts/jdk/jdk21/linux-x86/bin/javap';bind(javap)
x=subprocess.run([str(javap),'-p','-constants','-classpath',str(base),'com.android.internal.net.IGta3xlwifiNetpolicy$Stub'],capture_output=True,text=True);assert x.returncode==0;(O/'ordinals.txt').write_text(x.stdout+x.stderr)
names=['openSession','beginFrame','appendFrame','commitFrame','abandonFrame','readGeneration','closeSession','readStats','swapStats','acknowledgeStats','setStatsCounterset','removeUidAccounting','removeUidAccountingOnce','abortSession','pollLoopbackEvents','tagClatSocket']
for i,n in enumerate(names,1):assert re.search(r'TRANSACTION_'+n+r' = '+str(i)+r';',x.stdout),n
registry=T/'out/soong/.intermediates/external/iptables/extensions/libext_init/gen/initext.c';bind(registry);text=registry.read_text()
for n in ['guard','appid','raw_uid','raw_appid','owner_skip','non_loopback','lna','bad_iif','ingress_discard','iface_stats']:assert 'libxt_gta3xlwifi_'+n+'_init();' in text
permission=product/'obj/JAVA_LIBRARIES/services.permission_intermediates/javalib.jar';bind(permission)
for f in [Path(__file__),a.selection,log,exit_file,a.snapshot/'source-lock.json',a.build/'targets.txt']:bind(f)
for n,h in inputs.items():assert sha(Path(n))==h
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'actual_module_build_exit':0,'source_projects':1243,'exact_patches':20,'selected_sources':len(s['files']),'ELF_outputs':elf,'post_R8_DEX':dexes,'post_R8_Binder_identities':identities,'actual_Soong_AIDL_min31_sixteen_ordinals':True,'actual_iptables_registry_all_ten_matches':True,'services_permission_module_JAR_built':True,'selected_prebuilts_unchanged':True,'inputs_sha256':inputs,'hardware_tested':False,'full_ROM_built':False,'flash_ready':False},indent=2)+'\n');print('PASS: actual modules, post-R8 identities,16 ordinals,10 matches, native ELFs and unchanged inputs')
