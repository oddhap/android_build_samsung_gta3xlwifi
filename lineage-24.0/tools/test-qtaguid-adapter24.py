#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Test whole real qtaguid adapter/parser with synthetic procfs reads.

Only Android property/header types and FILE creation/close effects are fixtures.
Not a native ABI, actual procfs, socket, permission or networking-readiness test.
"""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);O=a.output.resolve();S=a.library.resolve()
(O/'netdbpf').mkdir();(O/'android-base').mkdir();(O/'log').mkdir();(O/'log/log.h').write_text('#pragma once\n')
(O/'netdbpf/BpfNetworkStats.h').write_text('''#pragma once
#include <cstdint>
#include <cstring>
#include <tuple>
#include <vector>
#include <sys/types.h>
namespace android::bpf {
constexpr int UID_ALL=-1,SET_ALL=-1,TAG_NONE=0;
struct StatsValue {uint64_t rxPackets=0,rxBytes=0,txPackets=0,txBytes=0;};
struct stats_line {char iface[16]{};int uid=0,set=0;uint32_t tag=0;int64_t rxBytes=0,rxPackets=0,txBytes=0,txPackets=0;
bool operator<(const stats_line& b)const {int c=strcmp(iface,b.iface);return c<0||(c==0&&std::tie(uid,set,tag)<std::tie(b.uid,b.set,b.tag));}};
}
''')
(O/'android-base/properties.h').write_text('''#pragma once
#include <cassert>
#include <string>
extern bool property;
namespace android::base {inline bool GetBoolProperty(const std::string& n,bool d){assert(n=="ro.gta3xlwifi.legacy_networking"&&!d);return property;}}
''')
(O/'shim.h').write_text('''#pragma once
#include <cstdio>
extern FILE* host_fopen(const char*,const char*);
extern int host_fclose(FILE*);
#define fopen host_fopen
#define fclose host_fclose
''')
harness=r'''
#include "Gta3xlwifiLegacyStats.h"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
using namespace android::bpf;
bool property=false;
static std::string detail,dev;
static int open_error,close_error;
static unsigned opens;
FILE* host_fopen(const char* name,const char* mode){
 assert(!strcmp(mode,"re"));++opens;if(open_error){errno=open_error;return nullptr;}
 const bool d=!strcmp(name,"/proc/net/xt_qtaguid/stats");assert(d||!strcmp(name,"/proc/net/xt_qtaguid/iface_stat_fmt"));
 const auto& text=d?detail:dev;FILE* f=tmpfile();assert(f);assert(fwrite(text.data(),1,text.size(),f)==text.size());rewind(f);return f;
}
int host_fclose(FILE* f){int r=fclose(f);assert(r==0);if(close_error){errno=close_error;return -1;}return 0;}
static const std::string dh="idx iface acct_tag_hex uid_tag_int cnt_set rx_bytes rx_packets tx_bytes tx_packets rx_tcp_bytes rx_tcp_packets rx_udp_bytes rx_udp_packets rx_other_bytes rx_other_packets tx_tcp_bytes tx_tcp_packets tx_udp_bytes tx_udp_packets tx_other_bytes tx_other_packets\n";
static const std::string vh="ifname total_skb_rx_bytes total_skb_rx_packets total_skb_tx_bytes total_skb_tx_packets rx_tcp_bytes rx_tcp_packets rx_udp_bytes rx_udp_packets rx_other_bytes rx_other_packets tx_tcp_bytes tx_tcp_packets tx_udp_bytes tx_udp_packets tx_other_bytes tx_other_packets\n";
static std::string row(int index,int uid,int set,const std::string& tag="0x0",const std::string& count="10"){
 return std::to_string(index)+" wlan0 "+tag+" "+std::to_string(uid)+" "+std::to_string(set)+" "+count+" 2 20 3 0 0 0 0 0 0 0 0 0 0 0 0\n";
}
int main(){unsigned cases=0;auto check=[&](bool v){assert(v);++cases;};
 check(!gta3xlwifiLegacyStatsEnabled());property=true;check(gta3xlwifiLegacyStatsEnabled());
 StatsValue out{};out.rxBytes=777;detail=dh+row(2,10001,0)+row(3,10001,1)+row(4,10001,0,"0x100000000")+row(5,10002,0);
 check(gta3xlwifiLegacyUidStats(10001,&out)==0&&out.rxBytes==20&&out.txBytes==40&&out.rxPackets==4&&out.txPackets==6);
 check(gta3xlwifiLegacyUidStats(10003,&out)==0&&out.rxBytes==0&&out.txBytes==0);
 dev=vh+"wlan0 10 2 20 3 0 0 0 0 0 0 0 0 0 0 0 0\nrmnet0 30 4 40 5 0 0 0 0 0 0 0 0 0 0 0 0\n";
 check(gta3xlwifiLegacyIfaceStats(nullptr,&out)==0&&out.rxBytes==40&&out.txBytes==60);
 check(gta3xlwifiLegacyIfaceStats("wlan0",&out)==0&&out.rxBytes==10&&out.txBytes==20);
 check(gta3xlwifiLegacyIfaceStats("missing0",&out)==0&&out.rxBytes==0);
 for(int mode=0;mode<4;++mode){out.rxBytes=777;out.txBytes=888;open_error=mode==0?EACCES:0;close_error=mode==1?EIO:0;detail=mode==2?"":mode==3?dh+row(2,10001,0,"0x0","9223372036854775807")+row(3,10001,1):dh+row(2,10001,0);
  int expected=mode==0?-EACCES:mode==1?-EIO:mode==2?-EINVAL:-EOVERFLOW;
  check(gta3xlwifiLegacyUidStats(10001,&out)==expected&&out.rxBytes==777&&out.txBytes==888);
 }
 open_error=close_error=0;detail=dh;check(gta3xlwifiLegacyUidStats(10001,&out)==0&&out.rxBytes==0&&out.txBytes==0);
 std::vector<stats_line> lines(1);lines[0].uid=777;detail="bad";check(gta3xlwifiLegacyDetail(&lines)==-EINVAL&&lines.size()==1&&lines[0].uid==777);
 detail=dh+row(2,10002,1)+row(3,10001,0);check(gta3xlwifiLegacyDetail(&lines)==0&&lines.size()==2&&lines[0].uid==10001&&lines[1].set==1&&lines[0].rxBytes==10);
 check(gta3xlwifiLegacyDev(&lines)==0&&lines.size()==2&&lines[0].uid==UID_ALL&&lines[0].set==SET_ALL&&lines[0].tag==TAG_NONE);
 auto before=opens;check(gta3xlwifiLegacyUidStats(10001,nullptr)==-EINVAL);check(gta3xlwifiLegacyDetail(nullptr)==-EINVAL);check(gta3xlwifiLegacyDev(nullptr)==-EINVAL);check(gta3xlwifiLegacyIfaceStats(nullptr,nullptr)==-EINVAL);check(opens==before);
 std::cout<<"passed_cases="<<cases<<"\n";
}
'''
(O/'test.cpp').write_text(harness);compiler=shutil.which('clang++') or shutil.which('c++');assert compiler
flags=[compiler,'-std=c++20','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O),'-I'+str(S)];cmds=[]
for name in ['Gta3xlwifiLegacyStats','QtaguidStats']:
 cmd=flags+(['-include',str(O/'shim.h')] if name=='Gta3xlwifiLegacyStats' else [])+['-c',str(S/(name+'.cpp')),'-o',str(O/(name+'.o'))];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr;cmds.append(cmd)
cmd=flags+[str(O/'test.cpp'),str(O/'Gta3xlwifiLegacyStats.o'),str(O/'QtaguidStats.o'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr;cmds.append(cmd)
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env);assert r.returncode==0 and not r.stderr and r.stdout=='passed_cases=20\n',(r.returncode,r.stdout,r.stderr)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inputs={str(path):sha(path) for path in [Path(__file__).resolve(),*[S/n for n in ['Gta3xlwifiLegacyStats.cpp','Gta3xlwifiLegacyStats.h','QtaguidStats.cpp','QtaguidStats.h']]]}
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':20,'stderr':r.stderr,'commands':cmds,'inputs_sha256':inputs,'hardware_tested':False},indent=2)+'\n');print('PASS: 20 actual qtaguid adapter/parser cases, fatal UBSan and zero stderr')
