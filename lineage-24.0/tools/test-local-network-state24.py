#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Canonical LNA state versus actual selected kernel Patricia lookup/canonical C.

Bounded queries use an independent bit-by-bit reference. Socket/UID permission
application and actual kernel packets are not exercised by this value test.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','kernel','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();K=a.kernel.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=K/'net/netfilter/gta3xlwifi_local_network.c';text=source.read_text();header=K/'include/uapi/linux/netfilter/gta3xlwifi_local_network.h';dst=O/'include/linux/netfilter/gta3xlwifi_local_network.h';dst.parent.mkdir(parents=True);dst.write_bytes(header.read_bytes())
code='''#include <stdbool.h>\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n#include <linux/netfilter/gta3xlwifi_local_network.h>\n#include <errno.h>\ntypedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;\n#define LNA_NONE (-1)\n#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))\n'''
for n in ['lna_node','lna_table']:
 start=text.index('struct '+n+' {');end=text.index('};',start)+2;code+=text[start:end]+'\n'
for n in ['lna_prefix','lna_bit','lna_canonical','lna_node_new','lna_insert','lna_lookup']:code+=m.extract(text,n)+'\n'
code+='''static struct lna_table table;\nvoid oracle_clear(void){free(table.nodes);memset(&table,0,sizeof(table));table.root=-1;}\nint oracle_set(const struct gta3xlwifi_lna_entry*entries,unsigned count){oracle_clear();table.count=count;table.nodes=calloc(2*count,sizeof(*table.nodes));if(count&&!table.nodes)return -ENOMEM;for(unsigned i=0;i<count;i++){int r=lna_insert(&table,entries+i);if(r)return r;}return 0;}\nint oracle_lookup(const unsigned char*key,bool*value){return lna_lookup(&table,key,value);}\nvoid oracle_canonical(unsigned char*key,unsigned bits){lna_canonical(key,bits);}\n''';(O/'oracle.c').write_text(code)
java=A/'packages/modules/Connectivity/common/src/com/android/net/module/util/bpf/LocalNetUidHostAllowlistKey.java';jt=java.read_text();assert 'this(/* lpmBitlen=*/32 + 32 + 128, uid, ifIndex, remoteAddress);' in jt and 'this(/* lpmBitlen=*/32 + 32, uid, ifIndex, Inet6Address.ANY);' in jt
code=r'''
#include "Gta3xlwifiLocalNetworkState.h"
#include <linux/netfilter/gta3xlwifi_local_network.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <algorithm>
using namespace android::net::gta3xlwifi;
using State=LocalNetworkState;using Entry=State::Entry;using Table=State::Table;
extern "C" {void oracle_clear();int oracle_set(const gta3xlwifi_lna_entry*,unsigned);int oracle_lookup(const unsigned char*,bool*);void oracle_canonical(unsigned char*,unsigned);}
static unsigned cases,comparisons;static uint32_t randomState=0x12345678;
#define C(x) do{++cases;assert(x);}while(0)
uint32_t random32(){randomState^=randomState<<13;randomState^=randomState>>17;randomState^=randomState<<5;return randomState;}
bool same(const Entry&a,const Entry&b){return a==b;}
void check(const State&s,Table t,const Entry&q,const std::vector<Entry>&entries){
 bool found=false,allowed=false,ef=false,ea=true;int longest=-1;
 for(const auto&e:entries){if(e.prefixBits>q.prefixBits)continue;bool match=true;for(unsigned bit=0;bit<e.prefixBits;bit++)if(((e.key[bit/8]^q.key[bit/8])>>(7-bit%8))&1){match=false;break;}if(match&&int(e.prefixBits)>longest){ef=true;ea=e.allowed;longest=e.prefixBits;}}
 assert(s.lookup(t,q,&found,&allowed)==0&&found==ef&&allowed==ea);++comparisons;
 if(q.prefixBits==192){bool kv=true;bool kf=oracle_lookup(q.key.data(),&kv);assert(found==kf&&(!found||allowed==kv));++comparisons;}
}
Entry hostKey(unsigned uid,unsigned iface,unsigned bits,unsigned addr,bool allowed){Entry e={bits,{},allowed};memcpy(e.key.data(),&uid,4);memcpy(e.key.data()+4,&iface,4);e.key[8]=addr;return e;}
int main(){
 State s;std::vector<Entry> n,h;bool found=true,allowed=false;Entry empty={0,{},false};
 C(State::canonicalize(nullptr)==-EINVAL);Entry bad={193,{},false};bad.key[23]=1;Entry copy=bad;C(State::canonicalize(&bad)==-EINVAL&&same(bad,copy));
 C(s.snapshot(nullptr,&h)==-EINVAL);C(s.snapshot(&n,&n)==-EINVAL);C(s.lookup(Table::Network,empty,nullptr,&allowed)==-EINVAL&&!allowed);C(s.lookup(Table::Network,empty,&found,&found)==-EINVAL&&found);
 C(s.set(static_cast<Table>(2),empty)==-EINVAL);C(s.erase(static_cast<Table>(2),empty)==-EINVAL);C(s.lookup(static_cast<Table>(2),empty,&found,&allowed)==-EINVAL&&found&&!allowed);
 C(s.lookup(Table::Network,empty,&found,&allowed)==0&&!found&&allowed);
 for(unsigned bits=0;bits<=192;bits++){Entry e={bits,{},true};for(auto&b:e.key)b=random32();auto expected=e.key;oracle_canonical(expected.data(),bits);C(State::canonicalize(&e)==0&&e.key==expected);C(s.set(Table::Network,e)==0);}
 C(s.snapshot(&n,&h)==0&&n.size()==193&&h.empty());for(size_t i=0;i<n.size();i++)C(n[i].prefixBits==i);
 Entry duplicate=empty;duplicate.key.fill(255);auto before=n;C(s.replace({empty,duplicate},{})==-EEXIST);C(s.snapshot(&n,&h)==0&&n==before&&h.empty());
 C(s.replace({}, {bad})==-EINVAL);C(s.snapshot(&n,&h)==0&&n==before);C(s.replace(std::vector<Entry>(1001,empty),{})==-ENOSPC);
 C(s.replace({hostKey(7,8,192,9,true),empty},{})==0);C(s.snapshot(&n,&h)==0&&n.front().prefixBits==0&&n.back().prefixBits==192);
 C(s.erase(Table::Network,duplicate)==0);C(s.snapshot(&n,&h)==0&&n.size()==1);C(s.erase(Table::Network,duplicate)==0);
 // Real Java constructors use UID+interface64 and UID+interface+host192.
 auto wildcard=hostKey(10001,17,64,0,true),specific=hostKey(10001,17,192,0xfd,false),other=hostKey(10002,17,64,0,true);
 C(s.replace({}, {specific,wildcard,other,empty})==0);C(s.lookup(Table::Host,specific,&found,&allowed)==0&&found&&!allowed);auto q=specific;q.key[8]=0xfe;C(s.lookup(Table::Host,q,&found,&allowed)==0&&found&&allowed);q.prefixBits=64;C(s.lookup(Table::Host,q,&found,&allowed)==0&&found&&allowed);
 C(s.removeUid(-1)==-EINVAL);C(s.removeUid(10001)==0);C(s.snapshot(&n,&h)==0&&h.size()==2);C(s.lookup(Table::Host,specific,&found,&allowed)==0&&found&&!allowed);C(s.lookup(Table::Host,other,&found,&allowed)==0&&found&&allowed);
 C(s.replace({}, {})==0);for(unsigned i=0;i<1000;i++){Entry e={192,{},true};e.key[22]=i>>8;e.key[23]=i;C(s.set(Table::Network,e)==0);C(s.set(Table::Host,e)==0);}C(s.set(Table::Network,empty)==-ENOSPC);C(s.set(Table::Host,empty)==-ENOSPC);Entry full={192,{},false};C(s.set(Table::Network,full)==0);C(s.snapshot(&n,&h)==0&&n.size()==1000&&h.size()==1000&&!n[0].allowed);C(s.erase(Table::Network,full)==0);C(s.set(Table::Network,empty)==0);
 for(unsigned round=0;round<120;round++){
  C(s.replace({}, {})==0);for(unsigned i=0;i<100;i++){Entry e={random32()%193,{},bool(random32()&1)};for(auto&b:e.key)b=random32();C(s.set(Table::Network,e)==0);e.allowed=!e.allowed;C(s.set(Table::Host,e)==0);}
  C(s.snapshot(&n,&h)==0);for(auto pair:{std::make_pair(Table::Network,&n),std::make_pair(Table::Host,&h)}){
   std::vector<gta3xlwifi_lna_entry>w;for(const auto&e:*pair.second){gta3xlwifi_lna_entry v={};v.prefix_bits=e.prefixBits;memcpy(v.key,e.key.data(),24);v.allowed=e.allowed;w.push_back(v);}C(oracle_set(w.data(),w.size())==0);
   for(unsigned i=0;i<200;i++){Entry q={192,{},false};for(auto&b:q.key)b=random32();check(s,pair.first,q,*pair.second);q.prefixBits=random32()%193;check(s,pair.first,q,*pair.second);}
  }
 }
 oracle_clear();printf("passed_cases=%u oracle_comparisons=%u\n",cases,comparisons);
}
''';(O/'test.cpp').write_text(code);commands=[['cc','-std=gnu11','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(O/'include'),'-c',str(O/'oracle.c'),'-o',str(O/'oracle.o')],['c++','-std=c++17','-Wall','-Wextra','-Werror','-pthread','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(S),'-I'+str(O/'include'),str(S/'Gta3xlwifiLocalNetworkState.cpp'),str(O/'test.cpp'),str(O/'oracle.o'),'-o',str(O/'test')]]
for i,cmd in enumerate(commands):
 x=subprocess.run(cmd,capture_output=True,text=True);(O/('compile-'+str(i)+'.log')).write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+) oracle_comparisons=(\d+)\n',x.stdout);assert m and int(m[2])>=144000
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,source,header,java,O/'oracle.c',O/'test.cpp',S/'Gta3xlwifiLocalNetworkState.cpp',S/'Gta3xlwifiLocalNetworkState.h',S/'Gta3xlwifiNetpolicyLease.h'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'oracle_comparisons':int(m[2]),'inputs_sha256':{str(p):sha(p) for p in paths},'commands':commands,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual kernel Patricia/canonical C, fatal UBSan')
