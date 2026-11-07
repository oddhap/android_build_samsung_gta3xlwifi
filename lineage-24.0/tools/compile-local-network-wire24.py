#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check actual ARM32/ARM64 LNA ioctl wire ABI using existing A17 Soong commands.

Only isolated compile/link objects and source/hash audits. No ioctl, tablet,
keyring or production output is accessed for mutation; not a transport/provider.
"""
import argparse,fcntl,hashlib,json,shlex,struct,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','kernel','snapshot','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();K=a.kernel.resolve();O=a.output.resolve();assert not O.exists() and not O.is_relative_to(T)
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir();inputs={};sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def bind(p):inputs[str(p.resolve())]=sha(p)
audit=Path(__file__).with_name('audit-port.py');bind(audit);bind(Path(__file__))
def check(name):subprocess.run([sys.executable,str(audit),str(T),str(a.snapshot),str(O/name)],check=True)
check('source-before.json')
try:
 h=K/'include/uapi/linux/netfilter/gta3xlwifi_local_network.h';dest=O/'include/linux/netfilter/gta3xlwifi_local_network.h';dest.parent.mkdir(parents=True);dest.write_bytes(h.read_bytes());bind(h);bind(dest)
 source=O/'wire.cpp';source.write_text('''#include <linux/netfilter/gta3xlwifi_local_network.h>
static_assert(sizeof(gta3xlwifi_lna_transfer)==40);
static_assert(__builtin_offsetof(gta3xlwifi_lna_transfer,revision)==16);
static_assert(__builtin_offsetof(gta3xlwifi_lna_transfer,network_entries)==24);
static_assert(__builtin_offsetof(gta3xlwifi_lna_transfer,host_entries)==32);
static_assert(sizeof(gta3xlwifi_lna_entry)==32);
static_assert(__builtin_offsetof(gta3xlwifi_lna_entry,allowed)==28);
static_assert(sizeof(gta3xlwifi_lna_match)==4);
static_assert(GTA3XLWIFI_LNA_SET_IMAGE==0x40286757);
static_assert(GTA3XLWIFI_LNA_GET_IMAGE==0xc0286758);
extern "C" unsigned lna_wire_size(){return sizeof(gta3xlwifi_lna_transfer);}
''');bind(source)
 ninja=T/'prebuilts/build-tools/linux-x86/bin/ninja';bin=T/'prebuilts/clang/host/linux-x86/clang-r596125/bin';rows=[]
 for variant,cls,machine in [('android_arm64_armv8-a_static',2,183),('android_arm_armv8-a_static',1,40)]:
  original='out/soong/.intermediates/system/core/libgta3xlwifi_keyutils/libgta3xlwifi_keyutils/'+variant+'/obj/system/core/libgta3xlwifi_keyutils/keyutils.o';bind(T/original)
  raw=subprocess.check_output([str(ninja),'-f','out/combined-lineage_gta3xlwifi.ninja','-t','commands','-s',original],cwd=T,text=True);assert len(raw.splitlines())==1;(O/(variant+'-command.txt')).write_text(raw);cmd=shlex.split(raw)
  if cmd[0]=='PWD=/proc/self/cwd':cmd=cmd[1:]
  if Path(cmd[0]).name=='ccache':cmd=cmd[1:]
  assert '-c' in cmd and cmd[-1]=='system/core/libgta3xlwifi_keyutils/keyutils.cpp'
  obj=O/(variant+'.o');cmd[cmd.index('-o')+1]=str(obj);cmd[cmd.index('-MF')+1]=str(obj)+'.d';cmd[-1]=str(source);cmd.insert(1,'-I'+str(O/'include'));bind(T/cmd[0]);r=subprocess.run(cmd,cwd=T,capture_output=True,text=True);(O/(variant+'-compile.log')).write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
  linked=O/(variant+'-native.o');link=[str(bin/'ld.lld'),'-r',str(obj),'-o',str(linked)];r=subprocess.run(link,cwd=T,capture_output=True,text=True);assert r.returncode==0 and not r.stderr,(r.stdout,r.stderr)
  data=linked.read_bytes();assert data[:7]==b'\x7fELF'+bytes([cls,1,1]) and struct.unpack_from('<HH',data,16)==(1,machine)
  rows.append({'variant':variant,'machine':machine,'elf_class':32 if cls==1 else 64,'compile_command':cmd,'link_command':link,'transfer_bytes':40,'entry_bytes':32,'match_bytes':4,'set_command':0x40286757,'get_command':0xc0286758})
 for f in [ninja,bin/'ld.lld']:bind(f)
 for f,h in inputs.items():assert sha(Path(f))==h
 check('source-after.json');(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'inputs_sha256':inputs,'actual_multilib_wire_checks':rows,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS actual A17 ARM32/ARM64 LNA ABI:40/32/4 bytes, offsets16/24/32, exact ioctl commands')
finally:
 if not (O/'source-after.json').exists():check('source-after.json')
