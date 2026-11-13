#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual non-consuming interface snapshot transport with syscall/wire fixtures.

Checks retry/reset, data/metadata validation and explicit real loss. Inherited
consumer logic is hash-bound to the last source test. Not real kernel counters
or global statistics/readiness publication.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();H=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();prior=H/'report.json';r=json.loads(prior.read_text());assert r['passed'];fixture=H/'test.cpp';assert sha(fixture)==r['inputs_sha256'][str(fixture)]
code=fixture.read_text().split('int main(){',1)[0].replace('extern "C" int __wrap_ioctl(', 'extern "C" int previousIoctl(',1)
code+=r'''
#include <linux/netfilter/gta3xlwifi_iface_stats.h>
using IS=NetpolicyLease::IfaceSnapshot;using IW=gta3xlwifi_iface_stats_entry;
static std::vector<IW> ifaceRows;static unsigned ifaceCalls,ifaceFault,ifaceError,ifaceRetries;static int ifaceErrno;static uint64_t ifaceLoss,ifaceSeq;
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);if(cmd!=GTA3XLWIFI_IFACE_STATS_GET)return previousIoctl(fd,cmd,arg);assert(files.count(fd)&&arg);++ifaceCalls;auto*t=reinterpret_cast<gta3xlwifi_iface_stats_transfer*>(arg);assert(t->version==1&&t->count==1000&&t->entries&&!t->lost_updates&&!t->update_sequence);auto*rows=reinterpret_cast<IW*>(uintptr_t(t->entries));std::copy(ifaceRows.begin(),ifaceRows.end(),rows);t->count=ifaceRows.size();t->lost_updates=ifaceLoss;t->update_sequence=ifaceSeq;
 if(ifaceRetries){--ifaceRetries;errno=EINTR;return -1;}if(ifaceError){errno=ifaceErrno;return -1;}
 switch(ifaceFault){case 0:break;case 1:t->version=2;break;case 2:t->count=1001;break;case 3:t->entries=77;break;case 4:rows[0].reserved=1;break;case 5:rows[0].ifindex=UINT32_MAX;break;case 6:rows[1].ifindex=rows[0].ifindex;break;case 7:std::swap(rows[0],rows[1]);break;default:assert(false);}return 0;
}
static void resetIface(){resetEvents();features=2047;ifaceRows.clear();ifaceCalls=ifaceFault=ifaceError=ifaceRetries=0;ifaceErrno=0;ifaceLoss=ifaceSeq=0;}
static IS sentinelIface(){IS s;s.lostUpdates=55;s.updateSequence=66;s.entries={{77,88,99,111,222}};return s;}
static bool unchangedIface(const IS&s){return s.lostUpdates==55&&s.updateSequence==66&&s.entries.size()==1&&s.entries[0].ifindex==77&&s.entries[0].txBytes==222;}
int main(){
 resetIface();{NetpolicyLease l;IS out=sentinelIface();C(l.readIfaceStats(nullptr)==-EINVAL&&ifaceCalls==0);C(l.readIfaceStats(&out)==-ENOTCONN&&unchangedIface(out));C(l.start()==0);C(l.readIfaceStats(&out)==0&&out.entries.empty()&&!out.lostUpdates);ifaceRows={{0,0,1,64,2,128},{17,0,3,192,4,256}};ifaceSeq=88;ifaceLoss=7;C(l.readIfaceStats(&out)==0&&out.entries.size()==2&&out.entries[1].ifindex==17&&out.entries[1].txBytes==256&&out.lostUpdates==7&&out.updateSequence==88&&held);ifaceRetries=3;C(l.readIfaceStats(&out)==0&&ifaceRetries==0&&out.entries.size()==2);C(l.release()==0&&!held);ifaceSeq=0;ifaceLoss=UINT64_MAX;ifaceRows[0].tx_packets=UINT64_MAX;C(l.readIfaceStats(&out)==0&&!held&&out.entries[0].txPackets==UINT64_MAX&&out.lostUpdates==UINT64_MAX&&out.updateSequence==0);}
 for(int feature:{0,255,1023}){resetIface();features=feature;NetpolicyLease l;IS out=sentinelIface();C(l.start()==0&&l.readIfaceStats(&out)==-EOPNOTSUPP&&unchangedIface(out)&&files.empty()&&held&&ifaceCalls==0);}
 resetIface();features=1024;{NetpolicyLease l;IS out;C(l.start()==0&&l.readIfaceStats(&out)==0&&held);}
 for(unsigned fault=1;fault<=7;fault++){resetIface();ifaceRows={{2,0,1,1,1,1},{17,0,2,2,2,2}};ifaceFault=fault;NetpolicyLease l;IS out=sentinelIface();C(l.start()==0&&l.readIfaceStats(&out)==-EPROTO&&unchangedIface(out)&&files.empty()&&held);}
 for(int error:{EFAULT,EIO,ENOMEM,ENOTTY}){resetIface();ifaceRows={{2,0,1,1,1,1}};ifaceError=1;ifaceErrno=error;NetpolicyLease l;IS out=sentinelIface();C(l.start()==0&&l.readIfaceStats(&out)==-error&&unchangedIface(out)&&files.empty()&&held);}
 resetIface();{for(unsigned i=0;i<1000;i++)ifaceRows.push_back({i,0,i,2*i,3*i,4*i});NetpolicyLease l;IS out;C(l.start()==0&&l.readIfaceStats(&out)==0&&out.entries.size()==1000&&out.entries.back().txBytes==3996);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(S/'Gta3xlwifiNetpolicyLease.cpp'),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=25
paths=[Path(__file__),prior,fixture,O/'test.cpp',S/'Gta3xlwifiNetpolicyLease.cpp',S/'Gta3xlwifiNetpolicyLease.h',*[p for p in (S/'linux/netfilter').glob('*.h')]]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':x.stderr,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
