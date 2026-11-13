#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual accounted-egress wrapper and unchanged real counters vs A17 arithmetic.

Reuses the hash-bound actual counter/XT/oracle harness. Policy return values,
skb, RCU grace and HOLD effects are fixtures; real pthreads exercise the outer
read-side lifetime. Actual policy and consume-once wrappers are regression-tested
separately. No installed producer rules or accounting readiness is claimed.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==49 and r['actual_A17_amount_comparisons']==786432
prior=R/'test.c';assert sha(prior)==r['inputs_sha256'][str(prior)]
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
source=S/'net/netfilter/gta3xlwifi_iface_stats.c';base=B/'net/netfilter/gta3xlwifi_iface_stats.c';assert sha(base)==r['inputs_sha256'][str(base)]
text=source.read_text();body=m.extract(text,'gta3xlwifi_accounted_egress');recovered=text
for line in ['#include <linux/netdevice.h>\n','#include <linux/rcupdate.h>\n','#include <net/gta3xlwifi_receive.h>\n']:assert recovered.count(line)==1;recovered=recovered.replace(line,'',1)
start=recovered.index('/* The interface producer ran in mangle POSTROUTING.');end=recovered.index('MODULE_LICENSE(',start);recovered=recovered[:start]+recovered[end:];assert recovered==base.read_text(),'Unexpected primitive change'
code=prior.read_text().split('int main(void){',1)[0]
code=code.replace('static unsigned cases,comparisons;','static unsigned cases;').replace('static int init_user_ns,other_ns;','static int init_user_ns;')
assert 'struct sk_buff{u32 len;uint16_t protocol;struct sock*sk;};' in code
code=code.replace('struct sk_buff{u32 len;uint16_t protocol;struct sock*sk;};','struct net_device;struct sk_buff{u32 len;uint16_t protocol;struct sock*sk;struct net_device*dev;};',1)
code+=r'''
static pthread_mutex_t rcu_mu=PTHREAD_MUTEX_INITIALIZER,decision_mu=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rcu_cv=PTHREAD_COND_INITIALIZER,decision_cv=PTHREAD_COND_INITIALIZER;
static __thread unsigned read_depth;
static unsigned readers;static bool hold_entered,held,pause_decision,decision_paused,continue_decision;
static int verdict,reader_result;
static void rcu_read_lock(void){assert(pthread_mutex_lock(&rcu_mu)==0);if(!read_depth++)++readers;assert(pthread_mutex_unlock(&rcu_mu)==0);}
static void rcu_read_unlock(void){assert(pthread_mutex_lock(&rcu_mu)==0);assert(read_depth);if(!--read_depth)--readers;pthread_cond_broadcast(&rcu_cv);assert(pthread_mutex_unlock(&rcu_mu)==0);}
static int gta3xlwifi_egress_policy(struct sock*sk,struct sk_buff*skb){(void)sk;(void)skb;assert(read_depth);rcu_read_lock();int result=verdict;rcu_read_unlock();assert(pthread_mutex_lock(&decision_mu)==0);if(pause_decision){decision_paused=true;pthread_cond_broadcast(&decision_cv);while(!continue_decision)pthread_cond_wait(&decision_cv,&decision_mu);}assert(pthread_mutex_unlock(&decision_mu)==0);return result;}
'''+body+r'''
static void*run_reader(void*p){reader_result=gta3xlwifi_accounted_egress(NULL,p);return NULL;}
static void*run_hold(void*p){(void)p;assert(pthread_mutex_lock(&rcu_mu)==0);hold_entered=true;pthread_cond_broadcast(&rcu_cv);while(readers)pthread_cond_wait(&rcu_cv,&rcu_mu);held=true;assert(pthread_mutex_unlock(&rcu_mu)==0);return NULL;}
int main(void){
 unsigned before=cases;struct net_device dev={17};struct sk_buff frame={.dev=&dev};
 const unsigned lengths[]={0,1,1500,1501,4096,65535};const int results[]={0,-EPERM,-EOPNOTSUPP,-ENOMEM,1};
 for(unsigned family=0;family<2;family++)for(unsigned i=0;i<6;i++)for(unsigned j=0;j<5;j++){
  reset_store();memset(&oracle_value,0,sizeof(oracle_value));frame.len=lengths[i];frame.protocol=htons(family?ETH_P_IPV6:ETH_P_IP);frame.dev=&dev;verdict=results[j];
  struct __sk_buff oracle={frame.len,frame.protocol,0,NULL};u32 key=0;
  T(gta3xlwifi_iface_account(&frame,17,true,false)==0);update_iface_stats_map(&oracle,&key,(struct egress_bool){true},(struct kver_uint){(4<<16)|(9<<8)},(struct undo_bool){false});
  T(gta3xlwifi_accounted_egress(NULL,&frame)==verdict);if(verdict)update_iface_stats_map(&oracle,&key,(struct egress_bool){true},(struct kver_uint){(4<<16)|(9<<8)},(struct undo_bool){true});
  T(iface_count==1&&iface_rows[0].tx_packets==oracle_value.txPackets&&iface_rows[0].tx_bytes==oracle_value.txBytes&&!iface_rows[0].rx_packets&&!iface_rows[0].rx_bytes&&!readers&&!read_depth);T(iface_sequence==(unsigned)(verdict?2:1));
 }
 reset_store();verdict=-EPERM;frame.dev=NULL;frame.len=64;T(gta3xlwifi_iface_account(&frame,0,true,false)==0);T(gta3xlwifi_accounted_egress(NULL,&frame)==-EPERM&&iface_count==1&&iface_rows[0].ifindex==0&&!iface_rows[0].tx_packets&&!iface_rows[0].tx_bytes);T(gta3xlwifi_accounted_egress(NULL,NULL)==-EPERM&&iface_sequence==2);
 reset_store();frame.dev=&dev;T(gta3xlwifi_accounted_egress(NULL,&frame)==-EPERM&&iface_rows[0].tx_packets==UINT64_MAX&&iface_rows[0].tx_bytes==(u64)-64); /* Exact A17 unsigned UNDO without a prior producer. */
 reset_store();for(u32 n=0;n<1000;n++)assert(!gta3xlwifi_iface_account(&frame,n,true,false));dev.ifindex=1001;T(gta3xlwifi_iface_account(&frame,1001,true,false)==-ENOSPC);T(gta3xlwifi_accounted_egress(NULL,&frame)==-EPERM&&iface_lost_updates==2&&iface_count==1000);
 reset_store();dev.ifindex=17;frame.len=4096;assert(!gta3xlwifi_iface_account(&frame,17,true,false));pause_decision=true;verdict=-EPERM;pthread_t reader,holder;T(pthread_create(&reader,NULL,run_reader,&frame)==0);
 assert(pthread_mutex_lock(&decision_mu)==0);while(!decision_paused)pthread_cond_wait(&decision_cv,&decision_mu);assert(pthread_mutex_unlock(&decision_mu)==0);
 T(pthread_create(&holder,NULL,run_hold,NULL)==0);assert(pthread_mutex_lock(&rcu_mu)==0);while(!hold_entered)pthread_cond_wait(&rcu_cv,&rcu_mu);T(readers==1&&!held&&iface_rows[0].tx_packets>0);assert(pthread_mutex_unlock(&rcu_mu)==0);
 assert(pthread_mutex_lock(&decision_mu)==0);continue_decision=true;pthread_cond_broadcast(&decision_cv);assert(pthread_mutex_unlock(&decision_mu)==0);
 T(pthread_join(reader,NULL)==0&&pthread_join(holder,NULL)==0);T(reader_result==-EPERM&&held&&!readers&&!iface_rows[0].tx_packets&&!iface_rows[0].tx_bytes&&iface_sequence==2);
 printf("passed_cases=%u\n",cases-before);return 0;
}
'''
(O/'test.c').write_text(code);include=R/'include';cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-Wno-missing-field-initializers','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(include),str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
matches=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert matches and int(matches[1])>=240
paths=[Path(__file__),helper,R/'report.json',prior,source,base,O/'test.c']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(matches[1]),'actual_A17_counter_flow_comparisons':60,'unchanged_counter_module_identity':True,'outer_read_side_lifetime_through_UNDO':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
