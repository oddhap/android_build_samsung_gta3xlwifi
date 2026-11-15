#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Package a pinned source-built candidate with the actual selected Samsung boot rule.

Only an isolated boot artifact is written. No source/input selection, recovery,
partition, device operation or release signing occurs. Not a flash-ready package.
"""
import argparse,fcntl,hashlib,json,re,shlex,struct,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','kernel-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T);lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads(a.kernel_report.read_text());assert r['passed'] and r['actual_Image_all_modules_and_Gator_built'] and r['actual_UID_receipt_and_corrected_full_ioctl_routing_built'];image=a.kernel_report.with_name('Image');assert sha(image)=='7ece8d6fd70870811abfe5fd9f947311506f97233491b4016cde441de3578aec'
inputs={}
def bind(f):f=Path(f).resolve();inputs[str(f)]=sha(f)
for f in [Path(__file__),a.kernel_report,image,T/'device/samsung/gta3xlwifi/BoardConfig.mk',T/'device/samsung/gta3xlwifi/mkbootimg.mk']:bind(f)
prebuilt=T/'device/samsung/gta3xlwifi/prebuilt';before={n:sha(prebuilt/n) for n in ['Image','vendor.img','dtbo.img']}
board=(T/'device/samsung/gta3xlwifi/BoardConfig.mk').read_text();limit=int(re.search(r'BOARD_BOOTIMAGE_PARTITION_SIZE := (\d+)',board)[1]);assert limit==33554432 and 'AB_OTA_UPDATER := false' in board
ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';bind(ninja);raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s','out/target/product/gta3xlwifi/boot.img'],cwd=T,text=True);(O/'actual-boot-rule.txt').write_text(raw)
outer=shlex.split(raw);assert len(outer)==3 and outer[:2]==['/bin/bash','-c'];words=shlex.split(outer[2]);start=next(i for i,w in enumerate(words) if 'mkbootimg' in w);command=[]
for w in words[start:]:
 if w==')':break
 command.append(w.lstrip('(') if not command else w)
assert command[0]=='out/host/linux-x86/bin/mkbootimg' and command.count('--kernel')==command.count('--output')==1 and '--ramdisk' not in command
command[0]=str(T/command[0]);command[command.index('--kernel')+1]=str(image.resolve());boot=O/'candidate-boot.img';command[command.index('--output')+1]=str(boot)
assert command[command.index('--header_version')+1]=='1' and command[command.index('--pagesize')+1]=='2048' and 'androidboot.selinux=enforcing' in command[command.index('--cmdline')+1];bind(Path(command[0]))
x=subprocess.run(command,cwd=T,capture_output=True,text=True);(O/'mkbootimg.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
check=T/'device/samsung/gta3xlwifi/check-ramdisk-size.py';bind(check);x=subprocess.run(['python3',str(check),str(boot)],cwd=T,capture_output=True,text=True);(O/'ramdisk-check.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
with boot.open('ab') as f:f.write(b'SEANDROIDENFORCE')
data=boot.read_bytes();assert data[:8]==b'ANDROID!' and data.endswith(b'SEANDROIDENFORCE') and len(data)<=limit
kernel_size=struct.unpack_from('<I',data,8)[0];ramdisk_size=struct.unpack_from('<I',data,16)[0];pagesize=struct.unpack_from('<I',data,36)[0];version=struct.unpack_from('<I',data,40)[0]
assert version==1 and pagesize==2048 and ramdisk_size==0 and kernel_size==image.stat().st_size
assert hashlib.sha256(data[pagesize:pagesize+kernel_size]).hexdigest()==sha(image)
for f,h in inputs.items():assert sha(Path(f))==h
assert {n:sha(prebuilt/n) for n in before}==before
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'kernel_sha256':sha(image),'candidate_boot_sha256':sha(boot),'boot_size':len(data),'physical_partition_size':limit,'remaining_bytes':limit-len(data),'actual_rule_command':command,'header_version':version,'pagesize':pagesize,'ramdisk_size':ramdisk_size,'Samsung_trailer_present':True,'kernel_payload_exact':True,'inputs_sha256':inputs,'selected_prebuilts':before,'source_or_input_selection_changed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: isolated exact kernel boot image',len(data),'bytes; margin',limit-len(data),'bytes; no selected input changed')
