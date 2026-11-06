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
p.add_argument('--kernel',type=Path,required=True);p.add_argument('--filesystem-config',type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);O=a.output.resolve();S=a.library.resolve()
(O/'private').mkdir();config=a.filesystem_config.read_text();assert '#define AID_NET_BW_STATS 3006' in config and '#define AID_ROOT 0' in config
(O/'private/android_filesystem_config.h').write_text('#pragma once\n#define AID_ROOT 0\n#define AID_NET_BW_STATS 3006\n')
ks=a.kernel.read_text();start=ks.index('static bool can_read_other_uid_stats(');predicate=ks[start:ks.index('\n}',start)+3]
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
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
extern int host_fstat(int,struct stat*);
extern int host_fstatfs(int,struct statfs*);
extern gid_t host_getegid();
extern int host_getgroups(int,gid_t*);
#define fstat host_fstat
#define fstatfs host_fstatfs
#define getegid host_getegid
#define getgroups host_getgroups
extern FILE* host_fopen(const char*,const char*);
extern int host_fclose(FILE*);
#define fopen host_fopen
#define fclose host_fclose
''')
harness=r'''
#include "Gta3xlwifiLegacyStats.h"
#include <cassert>
#include <algorithm>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <private/android_filesystem_config.h>
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
static gid_t file_gid=3006,egid=1000;
static uid_t file_uid=0,fsuid=1000;
static mode_t file_mode=S_IFREG|0440;
static unsigned long fs_magic=0x9fa0;
static int stat_error,fs_error,group_count_error,group_copy_error;
static int group_count_override=-1,group_copy_override=-1;
static std::vector<gid_t> groups{3006};
static void resetAccess(){file_gid=3006;egid=1000;file_uid=0;fsuid=1000;file_mode=S_IFREG|0440;fs_magic=0x9fa0;stat_error=fs_error=group_count_error=group_copy_error=0;group_count_override=group_copy_override=-1;groups={3006};}
int host_fstat(int fd,struct stat* st){assert(fd>=0);if(stat_error){errno=stat_error;return -1;}*st={};st->st_mode=file_mode;st->st_uid=file_uid;st->st_gid=file_gid;return 0;}
int host_fstatfs(int fd,struct statfs* st){assert(fd>=0);if(fs_error){errno=fs_error;return -1;}*st={};st->f_type=fs_magic;return 0;}
gid_t host_getegid(){return egid;}
int host_getgroups(int size,gid_t* out){
 if(size==0){if(group_count_error){errno=group_count_error;return -1;}return group_count_override>=0?group_count_override:groups.size();}
 if(group_copy_error){errno=group_copy_error;return -1;}
 int count=group_copy_override>=0?group_copy_override:groups.size();
 for(int i=0;i<std::min(size,count)&&i<int(groups.size());++i)out[i]=groups[i];
 return count;
}
using kuid_t=unsigned;
static int init_user_ns;
static unsigned from_kuid(const void*,unsigned uid){return uid;}
static unsigned current_fsuid(){return fsuid;}
static bool uid_eq(unsigned a,unsigned b){return a==b;}
static bool in_egroup_p(gid_t gid){return gid==egid||std::find(groups.begin(),groups.end(),gid)!=groups.end();}
struct ProcEntry{unsigned uid=0;gid_t gid=0;};
static ProcEntry stats{0,3006},ctrl;
static ProcEntry *xt_qtaguid_stats_file=&stats,*xt_qtaguid_ctrl_file=&ctrl;
static bool proc_stats_readall_limited=true;
#define unlikely(x) (x)
/*KERNEL_READ_PREDICATE*/
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
 resetAccess();check(can_read_other_uid_stats(10001));stats.gid=0;check(!can_read_other_uid_stats(10001));stats.gid=3006;
 detail=dh+row(2,10001,0);
 const int errors[]={-ENODEV,-ENODEV,-EACCES,-EACCES,-EACCES,-EACCES,-EIO,-EIO,-EIO,-EOVERFLOW,-EOVERFLOW};
 for(int mode=0;mode<11;++mode){resetAccess();out.rxBytes=777;out.txBytes=888;
  switch(mode){case 0:fs_magic=0x1234;break;case 1:file_mode=S_IFDIR|0440;break;case 2:file_uid=1000;break;case 3:file_gid=0;break;case 4:groups.clear();break;case 5:stat_error=EACCES;break;case 6:fs_error=EIO;break;case 7:group_count_error=EIO;break;case 8:group_copy_error=EIO;break;case 9:group_count_override=65537;break;case 10:group_copy_override=2;break;}
  check(gta3xlwifiLegacyUidStats(10001,&out)==errors[mode]&&out.rxBytes==777&&out.txBytes==888);
 }
 resetAccess();groups.clear();egid=3006;group_count_error=EIO;check(gta3xlwifiLegacyUidStats(10001,&out)==0&&out.rxBytes==10);
 resetAccess();file_gid=0;groups.clear();check(gta3xlwifiLegacyIfaceStats("wlan0",&out)==0&&out.rxBytes==10);
 resetAccess();group_copy_override=0;out.rxBytes=777;check(gta3xlwifiLegacyUidStats(10001,&out)==-EACCES&&out.rxBytes==777);
 resetAccess();fsuid=0;groups.clear();check(can_read_other_uid_stats(10001)&&gta3xlwifiLegacyUidStats(10001,&out)==-EACCES);
 resetAccess();
 auto before=opens;check(gta3xlwifiLegacyUidStats(10001,nullptr)==-EINVAL);check(gta3xlwifiLegacyDetail(nullptr)==-EINVAL);check(gta3xlwifiLegacyDev(nullptr)==-EINVAL);check(gta3xlwifiLegacyIfaceStats(nullptr,nullptr)==-EINVAL);check(opens==before);
 std::cout<<"passed_cases="<<cases<<"\n";
}
'''
harness=harness.replace('/*KERNEL_READ_PREDICATE*/',predicate)
(O/'test.cpp').write_text(harness);compiler=shutil.which('clang++') or shutil.which('c++');assert compiler
flags=[compiler,'-std=c++20','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O),'-I'+str(S)];cmds=[]
for name in ['Gta3xlwifiLegacyStats','QtaguidStats']:
 cmd=flags+(['-include',str(O/'shim.h')] if name=='Gta3xlwifiLegacyStats' else [])+['-c',str(S/(name+'.cpp')),'-o',str(O/(name+'.o'))];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr;cmds.append(cmd)
cmd=flags+[str(O/'test.cpp'),str(O/'Gta3xlwifiLegacyStats.o'),str(O/'QtaguidStats.o'),'-o',str(O/'test')];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr;cmds.append(cmd)
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';r=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env);assert r.returncode==0 and not r.stderr and r.stdout=='passed_cases=37\n',(r.returncode,r.stdout,r.stderr)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inputs={str(path):sha(path) for path in [Path(__file__).resolve(),*[S/n for n in ['Gta3xlwifiLegacyStats.cpp','Gta3xlwifiLegacyStats.h','QtaguidStats.cpp','QtaguidStats.h']],a.kernel.resolve(),a.filesystem_config.resolve()]}
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':37,'stderr':r.stderr,'commands':cmds,'inputs_sha256':inputs,'hardware_tested':False},indent=2)+'\n');print('PASS: 37 actual qtaguid adapter/parser cases, fatal UBSan and zero stderr')
