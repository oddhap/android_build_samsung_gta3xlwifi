#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute actual listener selection and AOSP packet reporting/enforcement control flow.

Java service collaborators and BPF map/syscall primitives are explicit fixtures.
Kernel4.4 observation remains unavailable; no successful hardware test is claimed.
"""
import argparse,fcntl,hashlib,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser()
for n in ['composition','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();C=a.composition;O=a.output;assert not O.exists();lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir()
T=Path('/srv/android/src/lineage-24.0-arm64');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();inputs={}
def read(p):inputs[str(p)]=sha(p);return p.read_text()
def run(cmd):
 x=subprocess.run(list(map(str,cmd)),capture_output=True,text=True);assert x.returncode==0,(cmd,x.stdout,x.stderr);return x.stdout
rel='packages/modules/Connectivity/service/src/com/android/server/ConnectivityService.java'
for folder,label in [('baseline','original'),('files','fixed')]:
 text=read(C/folder/rel);start=text.index('        if (mDeps.isAtLeastB()',text.index('mProxyTracker = multiProxyEnabled'));end=text.index('\n\n        mTelephonyManager',start);body=text[start:end]
 fixture='''class ListenerTest {
 static boolean legacy,sdk,metrics,notes;static int calls,cases;static Object mContext;
 static class Unavailable extends RuntimeException{}
 static class Handler{Object getLooper(){return null;}}
 static class Maps{boolean usesGta3xlwifiNetworking(){return legacy;}boolean isLocalNetMetricsEnabled(){return metrics;}boolean isAccessLocalNetworkPermissionEnabled(){return notes;}}
 static class Deps{boolean isAtLeastB(){return sdk;}Object getLocalNetEventListener(Object c,Object l,boolean m,boolean n){calls++;if(legacy)throw new Unavailable();if(m!=metrics||n!=notes)throw new AssertionError();return new Object();}}
 Handler mHandler=new Handler();Maps mBpfNetMaps=new Maps();Deps mDeps=new Deps();Object mLocalNetEventListener;
 void construct(){'''+body+'''}
 public static void main(String[]args){boolean original=args[0].equals("original");
 for(int bits=0;bits<16;bits++){legacy=(bits&1)!=0;sdk=(bits&2)!=0;metrics=(bits&4)!=0;notes=(bits&8)!=0;calls=0;ListenerTest t=new ListenerTest();boolean failed=false;try{t.construct();}catch(Unavailable e){failed=true;}
 if(original){if(legacy&&sdk){if(!failed||calls!=1)throw new AssertionError();cases++;}continue;}
 if(failed||calls!=(sdk&&!legacy?1:0)||(t.mLocalNetEventListener!=null)!=(sdk&&!legacy))throw new AssertionError("case "+bits);cases++;}
 System.out.println((original?"original_unsupported_listener_failures=":"listener_selection_cases=")+cases);}}
''';f=O/'ListenerTest.java';f.write_text(fixture);out=O/label;out.mkdir();javac=T/'prebuilts/jdk/jdk21/linux-x86/bin/javac';run([javac,'-d',out,f]);log=run([javac.with_name('java'),'-ea','-cp',out,'ListenerTest',label]);(O/(label+'.log')).write_text(log)
bpf=T/'packages/modules/Connectivity/bpf/progs/netd.c';text=read(bpf);start=text.index('function bool should_block_local_network_packets(');opening=text.index('{',start);end=opening+1;depth=1
while depth:depth+=(text[end]=='{')-(text[end]=='}');end+=1
body=text[start:end]
prefix=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
struct in6_addr{char bytes[16];};typedef uint16_t __be16;
typedef struct{struct in6_addr saddr,daddr;uint16_t sport,dport;uint8_t ip_proto;} SkbIpPacketData;
struct __sk_buff{int unused;};struct egress_bool{bool egress;};struct kver_uint{unsigned v;};
#define function static
#define KVER_IS_AT_LEAST(k,a,b) ((k).v>=((a)*100+(b)))
#define NS_PER_MINUTE (60ULL*1000*1000*1000)
#define BPF_ANY 0
static bool enabled,allowed,blocked;static int notes,queries;
typedef struct{uint32_t uid;}LocalNetNoteOp;static LocalNetNoteOp event;
static bool *bpf_local_net_note_op_enabled_map_lookup_elem(uint32_t*k){assert(*k==0);return &enabled;}
static uint32_t *bpf_local_net_note_op_cache_map_lookup_elem(const uint32_t*k){(void)k;return 0;}
static uint64_t bpf_ktime_get_boot_ns(void){return NS_PER_MINUTE;}
static LocalNetNoteOp*bpf_local_net_note_op_ringbuf_reserve(void){return &event;}
static void bpf_local_net_note_op_ringbuf_submit(LocalNetNoteOp*e){assert(e->uid==10001);notes++;}
static void bpf_local_net_note_op_cache_map_update_elem(const uint32_t*k,uint32_t*v,int flags){assert(*k==10001&&*v==1&&!flags);}
static bool is_local_net_access_allowed_cached(struct __sk_buff*s,uint32_t uid,uint32_t i,const struct in6_addr*r,uint8_t p,__be16 port,struct kver_uint k){(void)s;(void)i;(void)r;(void)p;(void)port;(void)k;assert(uid==10001);queries++;return allowed;}
static bool is_local_network_access_blocked(uint32_t uid){assert(uid==10001);return blocked;}
'''
suffix=r'''
int main(void){SkbIpPacketData p={0};struct __sk_buff s={0};unsigned cases=0;unsigned versions[]={404,509,510,601};for(unsigned i=0;i<4;i++)for(unsigned flags=0;flags<16;flags++){enabled=flags&1;allowed=flags&2;blocked=flags&4;bool egress=flags&8;notes=queries=0;bool result=should_block_local_network_packets(&p,&s,10001,17,(struct egress_bool){egress},(struct kver_uint){versions[i]});assert(result==(blocked&&!allowed));assert(notes==(versions[i]>=510&&enabled&&!allowed?1:0));if(versions[i]<510&&!blocked)assert(queries==0);cases++;}printf("AOSP_reporting_and_enforcement_cases=%u\n",cases);}
'''
f=O/'producer.c';f.write_text(prefix+body+suffix);run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',f,'-o',O/'producer']);log=run([O/'producer']);(O/'producer.log').write_text(log)
for f in [T/'packages/modules/Connectivity/service/src/com/android/server/BpfNetMaps.java',T/'packages/modules/Connectivity/service/src/com/android/server/connectivity/LocalNetEventListener.java',T/'packages/modules/Connectivity/service/native/libs/libeventpolling/LocalNetEventHandler.cpp']:
 if f.exists():read(f)
source=json.loads((C/'selection.json').read_text())['files'];inputs[str(Path(__file__).resolve())]=sha(Path(__file__).resolve())
(O/'report.json').write_text(json.dumps(dict(passed=True,scope=__doc__,source_sha256={n:v['after'] for n,v in source.items()},inputs_sha256=inputs,original_unsupported_listener_failures=4,listener_selection_cases=16,AOSP_reporting_and_enforcement_cases=64,modern_listener_flags_and_failure_behavior_retained=True,permission_flags_changed=False,enforcement_changed=False,legacy_local_network_note_ops_available=False,BPF_readiness_synthesized=False,hardware_tested=False),indent=2)+'\n');print((O/'fixed.log').read_text().strip());print(log.strip())
