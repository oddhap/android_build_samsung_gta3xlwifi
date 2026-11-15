#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual ARM32/ARM64 cleanup UAPI compile and relocatable links outside TOP."""
import argparse,fcntl,hashlib,json,struct,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','native-report','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
r=json.loads(a.native_report.read_text());assert r['passed'] and r['twelve_AIDL_ordinals_verified'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={str(a.native_report):sha(a.native_report),str(Path(__file__).resolve()):sha(Path(__file__))}
for n,h in r['inputs_sha256'].items():assert sha(Path(n))==h
wire=O/'receipt-wire.cpp';wire.write_text('''#include <linux/netfilter/gta3xlwifi_packet_stats.h>
static_assert(sizeof(gta3xlwifi_uid_cleanup)==64);
static_assert(__builtin_offsetof(gta3xlwifi_uid_cleanup,nonce)==16);
static_assert(__builtin_offsetof(gta3xlwifi_uid_cleanup,generation)==24);
static_assert(__builtin_offsetof(gta3xlwifi_uid_cleanup,active_epoch)==32);
static_assert(__builtin_offsetof(gta3xlwifi_uid_cleanup,reserved)==40);
static_assert(GTA3XLWIFI_UID_CLEANUP==0xc0406763U);
static_assert(GTA3XLWIFI_UID_CAP_UID_CLEANUP_RECEIPT==131072U);
extern "C" unsigned receipt_size(){return sizeof(gta3xlwifi_uid_cleanup);}
''');inputs[str(wire)]=sha(wire);commands=[]
for bit,machine in [('arm64',183),('arm',40)]:
 old=next(c.copy() for c in r['commands'] if c[-1].endswith('/names-wire.cpp') and ('android_'+bit+'_') in c[c.index('-o')+1])
 old.insert(1,'-I'+str(S/'include/uapi'));old[old.index('-o')+1]=str(O/(bit+'.o'));old[old.index('-MF')+1]=str(O/(bit+'.d'));old[-1]=str(wire)
 linker=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin/ld.lld';link=[str(linker),'-r',str(O/(bit+'.o')),'-o',str(O/(bit+'-linked.o'))]
 for name,c in [(bit,old),(bit+'-link',link)]:
  x=subprocess.run(c,cwd=T,capture_output=True,text=True);(O/(name+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr;commands.append(c)
 data=(O/(bit+'-linked.o')).read_bytes();assert data[:7]==b'\x7fELF'+bytes([2 if bit=='arm64' else 1,1,1]);assert struct.unpack_from('<HH',data,16)==(1,machine)
 for c in [old,link]:
  exe=Path(c[0]);exe=exe if exe.is_absolute() else T/exe;inputs[str(exe)]=sha(exe)
header=S/'include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h';inputs[str(header)]=sha(header)
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'actual_ARM32_ARM64_receipt64_offsets_and_ioctl_verified':True,'commands':commands,'inputs_sha256':inputs,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: ARM32/64 actual target UAPI64/offsets/ioctl and ELF links')
