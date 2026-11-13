#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual socket-owner hook bodies and ordering with source-bound LNA/LB fixtures.

The private table verdict is a fixture, not a real packet/table interpreter.
Real evaluator/snapshot is covered separately. Reuses the immutable prior actual
parser/LNA/loopback implementation and exercises DROP/PASS, DNS, CLAT, one UID
sample across inode mutations and actual pthread lease-drain ordering.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-kernel','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_kernel.resolve();H=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
report=H/'report.json';r=json.loads(report.read_text());assert r['passed']
prior=H/'test.c';assert sha(prior)==r['inputs_sha256'][str(prior)]
raw=S/'net/netfilter/xt_qtaguid.c';base=B/'net/netfilter/xt_qtaguid.c';new=raw.read_text();old=base.read_text();code=prior.read_text()
assert sha(base)==next(h for path,h in r['inputs_sha256'].items() if path.endswith('/net/netfilter/xt_qtaguid.c'))
recovered=new
for name in ['gta3xlwifi_receive_policy','gta3xlwifi_egress_policy']:
 assert m.extract(code,name)==m.extract(old,name)
 recovered=recovered.replace(m.extract(new,name),m.extract(old,name),1)
assert recovered==old,'Unexpected raw source change outside the two reviewed hook bodies'
code=code.replace('int main(void){','static int baseline_regression_main(void){',1)
# Simulate a live inode UID change during the real tag-query lock, without
# modifying any shipping source or its metadata/UID accessor implementation.
code='static int mutate_tag_uid;\n'+code
fn=m.extract(code,'get_sock_stat_nl');code=code.replace(fn,fn.replace('assert(tag_depth==1);','assert(tag_depth==1);if(mutate_tag_uid)((struct sock*)s)->uid=20002;',1))
code+=r'''
static unsigned owner_calls;static u32 owner_uid;static bool owner_direction,mutate_owner_uid;static int owner_result;
static int gta3xlwifi_socket_table_policy_uid(struct sock*s,struct sk_buff*b,bool output,u32 uid){assert(s==&receiver&&b&&rcu_depth);++owner_calls;owner_uid=uid;owner_direction=output;if(mutate_owner_uid)s->uid=20002;return gta3xlwifi_netpolicy_held()?-EPERM:owner_result;}
'''
has_meta='gta3xlwifi_socket_table_policy_meta(' in new
if has_meta:
 code+='\nstatic bool owner_dns;\nstatic int gta3xlwifi_socket_table_policy_meta(struct sock*s,struct sk_buff*b,bool output,u32 uid,bool dns){owner_dns=dns;return gta3xlwifi_socket_table_policy_uid(s,b,output,uid); }\n'
for name in ['gta3xlwifi_receive_policy','gta3xlwifi_egress_policy']:
 code+='\n'+m.extract(new,name).replace('int '+name+'(', 'static int candidate_'+name+'(',1)+'\n'
code+=r'''
static bool candidate_output;
static int candidate(struct sk_buff*s,bool output){return output?candidate_gta3xlwifi_egress_policy(&receiver,s):candidate_gta3xlwifi_receive_policy(&receiver,s);}
static void*candidate_reader(void*s){receive_result=candidate(s,candidate_output);return NULL;}
static void owner_reset(void){owner_calls=0;owner_uid=999;owner_direction=false;owner_result=0;mutate_owner_uid=false;mutate_tag_uid=0;tagged_sk=NULL;module_passive=false;receiver.uid=10001;receiver.sk_family=AF_INET;receiver.full=true;device.ifindex=17;peer_known=true;peer_uid=110001;clear_events();}
int main(void){
 assert(baseline_regression_main()==0);unsigned before=cases;
 T(netpolicy_open(NULL,&owner)==0);struct gta3xlwifi_lna_entry deny={.allowed=0};struct gta3xlwifi_lna_transfer lna={1,1,0,0,1,(uintptr_t)&deny,0};T(io(GTA3XLWIFI_LNA_SET_IMAGE,&lna)==0);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
 struct sk_buff skb={.length=1166,.data_at=34,.network=-20,.protocol=htons(ETH_P_IP),.sk=&foreign,.dev=&device};skb.data[14]=0x45;skb.data[23]=17;skb.data[26]=192;skb.data[29]=7;skb.data[30]=192;skb.data[33]=8;
 for(unsigned family=0;family<2;family++)for(unsigned direction=0;direction<2;direction++){
  owner_reset();receiver.sk_family=family?AF_INET6:AF_INET;bool output=direction;
  owner_result=-EPERM;T(candidate(&skb,output)==-EPERM&&owner_calls==1&&owner_uid==10001&&owner_direction==output&&skb.sk==&foreign&&skb.network==-20&&skb.data_at==34);
  // Tagged DNS never bypasses ordinary DROP. A valid PASS permits only LNA's
  // DNS exception; a process UID alone is not a DNS identity.
  tagged_sk=&receiver;tagged.tag=((u64)0xffffff82<<32)|1051;T(candidate(&skb,output)==-EPERM&&owner_calls==2);owner_result=0;T(candidate(&skb,output)==0&&owner_calls==3);
  tagged.tag=((u64)0xffffff81<<32)|1051;T(candidate(&skb,output)==-EPERM&&owner_calls==4);
  tagged_sk=NULL;receiver.uid=1051;T(candidate(&skb,output)==-EPERM&&owner_uid==1051);receiver.uid=10001;
  // Parse failure still reaches ordinary owner. No early parser success bypass.
  u16 saved=skb.protocol;skb.protocol=0;owner_result=-EPERM;unsigned count=owner_calls;T(candidate(&skb,output)==-EPERM&&owner_calls==count+1);owner_result=0;T(candidate(&skb,output)==0);skb.protocol=saved;
  // Normalized actual socket identity, unrelated skb owner and creator identity.
  receiver.uid=65534;T(candidate(&skb,output)==0&&owner_uid==0);receiver.uid=10001;receiver.creator_uid=0;owner_result=-EPERM;T(candidate(&skb,output)==-EPERM&&owner_uid==10001);
  // UID is sampled BEFORE tag lookup can race an inode ownership change.
  mutate_tag_uid=1;count=owner_calls;T(candidate(&skb,output)==-EPERM&&owner_calls==count+1&&owner_uid==10001&&receiver.uid==20002);mutate_tag_uid=0;receiver.uid=10001;
  // Both the shared HOLD and unavailable tag metadata stop before the table.
  T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0);count=owner_calls;T(candidate(&skb,output)==-EPERM&&owner_calls==count);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);module_passive=true;T(candidate(&skb,output)==-EOPNOTSUPP&&owner_calls==count);module_passive=false;
 }
 owner_reset();owner_result=-EPERM;receiver.uid=1029;T(candidate(&skb,true)==0&&owner_calls==0);tagged_sk=&receiver;tagged.tag=10001;T(candidate(&skb,true)==-EPERM&&owner_calls==1);tagged.tag=1029;receiver.uid=10001;T(candidate(&skb,true)==0&&owner_calls==1);T(candidate(&skb,false)==-EPERM&&owner_calls==2);
 // No loopback check/event for an earlier ordinary DROP. DNS cannot exempt LB.
 owner_reset();device.ifindex=1;owner_result=-EPERM;unsigned lookups=peer_lookups;T(candidate(&skb,true)==-EPERM&&loopback_count==0&&peer_lookups==lookups);owner_result=0;tagged_sk=&receiver;tagged.tag=((u64)0xffffff82<<32)|1051;T(candidate(&skb,true)==-EPERM&&loopback_count==1&&loopback_events[loopback_head].sender_uid==10001);
 // A later inode UID change cannot change the sender recorded by actual LB.
 clear_events();mutate_owner_uid=true;T(candidate(&skb,true)==-EPERM&&owner_uid==10001&&receiver.uid==20002&&loopback_count==1&&loopback_events[loopback_head].sender_uid==10001);mutate_owner_uid=false;
 // LNA uses the same sampled UID, not a recapture after ordinary evaluation.
 T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_HOLD,0)==0);struct gta3xlwifi_uid_permission_entry entry={10001,1};struct gta3xlwifi_uid_permission_transfer perm={1,1,1,(uintptr_t)&entry};T(io(GTA3XLWIFI_UID_SET_IMAGE,&perm)==0);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
 for(unsigned direction=0;direction<2;direction++){owner_reset();mutate_owner_uid=true;T(candidate(&skb,direction)==0&&owner_uid==10001&&receiver.uid==20002);}
 // Actual RCU reader/lease grace synchronization remains across UID, tag and
 // table calls in each NEW body, using real pthread mutex/condition effects.
 for(unsigned direction=0;direction<2;direction++){
  owner_reset();candidate_output=direction;pause_tag=true;tag_entered=continue_tag=drain_entered=hold_done=false;pthread_t reader,holder;
  T(pthread_create(&reader,NULL,candidate_reader,&skb)==0);assert(pthread_mutex_lock(&rmu)==0);while(!tag_entered)pthread_cond_wait(&rcv,&rmu);assert(pthread_mutex_unlock(&rmu)==0);
  T(pthread_create(&holder,NULL,hold_thread,NULL)==0);assert(pthread_mutex_lock(&rmu)==0);while(!drain_entered)pthread_cond_wait(&rcv,&rmu);T(!hold_done&&active_readers>0);continue_tag=true;pthread_cond_broadcast(&rcv);assert(pthread_mutex_unlock(&rmu)==0);
  T(pthread_join(reader,NULL)==0&&pthread_join(holder,NULL)==0&&hold_result==0&&receive_result==-EPERM&&gta3xlwifi_netpolicy_held()&&active_readers==0);pause_tag=false;T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0);
 }
 T(netpolicy_flush(&owner,NULL)==0);T(netpolicy_release(NULL,&owner)==0);lna_free(lna_current);lna_current=NULL;vfree(uid_image);uid_image=NULL;T(allocs==frees&&!rcu_depth&&!tag_depth);printf("owner_passed_cases=%u\n",cases-before);
}
'''
if has_meta:
 code=code.replace('owner_result=0;T(candidate(&skb,output)==0&&owner_calls==3);','owner_result=0;T(candidate(&skb,output)==0&&owner_calls==3);T(owner_dns);')
 code=code.replace('tagged.tag=((u64)0xffffff81<<32)|1051;T(candidate(&skb,output)==-EPERM&&owner_calls==4);','tagged.tag=((u64)0xffffff81<<32)|1051;T(candidate(&skb,output)==-EPERM&&owner_calls==4);T(!owner_dns);')
(O/'test.c').write_text(code)
cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(H/'egress-regression/receive-prerequisite/include'),str(O/'test.c'),'-o',str(O/'test')]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,(r.returncode,r.stdout,r.stderr)
match=re.search(r'owner_passed_cases=(\d+)\n$',r.stdout);assert match and int(match[1])>=70
paths=[Path(__file__),helper,raw,base,report,prior,O/'test.c']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'inherited_reference_implementation_regressions':1797,'inputs_sha256':{str(p):sha(p) for p in paths},'reference_fixture_inputs_sha256':r if False else json.loads(report.read_text())['inputs_sha256'],'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(r.stdout.strip())
