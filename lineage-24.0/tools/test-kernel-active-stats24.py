#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual active-bank reader plus full prior storage/GSO/concurrency regression.

Kernel locks/copies/packets are host fixtures. Source outside the two reviewed
functions is byte-identical to the fully built runtime prerequisite.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
h=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');sp=importlib.util.spec_from_file_location('extract',h);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
r=json.loads((R/'report.json').read_text());assert r['passed'] and r['actual_A17_GSO_comparisons']==9830400 and sha(R/'test.c')==r['inputs_sha256'][str(R/'test.c')]
old=B/'net/netfilter/gta3xlwifi_packet_stats.c';new=S/'net/netfilter/gta3xlwifi_packet_stats.c';t=new.read_text();bt=old.read_text();recovered=t
for name in ['stats_read','gta3xlwifi_packet_stats_features']:recovered=recovered.replace(m.extract(t,name),m.extract(bt,name),1)
assert recovered==bt,'Changes outside active read/compiled feature'
code=(R/'test.c').read_text()
for name in ['stats_read','gta3xlwifi_packet_stats_features']:code=code.replace(m.extract(code,name),m.extract(t,name),1)
assert code.count('q.kind=3;')==1 and code.count('gta3xlwifi_packet_stats_features()==4096')==1
code=code.replace('q.kind=3;','q.kind=4;',1).replace('gta3xlwifi_packet_stats_features()==4096','gta3xlwifi_packet_stats_features()==36864',1).replace('int main(void){','static int previous_regressions(void){',1)
needle='printf("passed_cases=%u comparisons=%u concurrent_updates=80000\\n",cases,comparisons);';assert needle in code;code=code.replace(needle,needle+'return 0;',1)
configs=''
for inet,ipv6 in [(0,0),(1,0),(0,1),(1,1)]:
 configs+='\n#undef CONFIG_INET\n#undef CONFIG_IPV6\n'+('#define CONFIG_INET 1\n' if inet else '')+('#define CONFIG_IPV6 1\n' if ipv6 else '')+m.extract(t,'gta3xlwifi_packet_stats_features').replace('gta3xlwifi_packet_stats_features',f'features_{inet}{ipv6}',1)+'\n'
code+=configs
code+=r'''
static void check_active(u64 epoch){
 struct gta3xlwifi_packet_stats_entry rows[5000];struct gta3xlwifi_packet_stats_state before=state();
 struct gta3xlwifi_packet_stats_transfer q=req(GTA3XLWIFI_STATS_ACTIVE,epoch,rows,5000);
 T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.kind==3&&q.epoch==epoch&&q.count==before.bank_count[before.active_bank]&&q.lost_updates==before.bank_lost[before.active_bank]);
 struct gta3xlwifi_packet_stats_state after=state();T(!memcmp(&before,&after,sizeof(before)));
 for(u32 i=1;i<q.count;i++)T(stats_compare(&rows[i-1],&rows[i])<0);
}
int main(void){
 T(previous_regressions()==0);unsigned begin=cases;T(!features_00());T(!features_10());T(!features_01());T(features_11()==36864);reset_store();check_active(1);
 struct sk_buff packet={64,0,{1}};struct gta3xlwifi_packet_stats_entry rows[5000];
 for(u32 i=0;i<30;i++)gta3xlwifi_packet_stats_record(NULL,&packet,i%3,i%5,17+i%2,true);
 check_active(1);struct gta3xlwifi_packet_stats_transfer q=req(3,1,NULL,0);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==30&&q.sequence==30);
 q=req(3,0,rows,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-EINVAL);q=req(3,2,rows,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-ESTALE);
 q=req(3,1,rows,1);T(io(GTA3XLWIFI_STATS_READ,&q)==-ENOSPC);check_active(1);
 struct gta3xlwifi_packet_stats_swap flip_result=flip();T(flip_result.active_epoch==2);check_active(2);q=req(3,1,rows,5000);T(io(GTA3XLWIFI_STATS_READ,&q)==-ESTALE);
 for(unsigned fault=0;fault<3;fault++){struct gta3xlwifi_packet_stats_state before=state();q=req(3,2,rows,5000);if(fault==0)alloc_fault=true;else to_fault=to_calls+fault;T(io(GTA3XLWIFI_STATS_READ,&q)==(fault==0?-ENOMEM:-EFAULT));alloc_fault=false;to_fault=0;struct gta3xlwifi_packet_stats_state after=state();T(!memcmp(&before,&after,sizeof(before)));}
 reset_store();for(u32 i=0;i<5001;i++)gta3xlwifi_packet_stats_record(NULL,&packet,i,0,17,true);check_active(1);q=req(3,1,rows,5000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==5000&&q.lost_updates==1);
 reset_store();pthread_t threads[8];for(uintptr_t i=1;i<=8;i++)assert(!pthread_create(&threads[i-1],NULL,producer,(void*)i));
 for(unsigned sample=0;sample<100;sample++){
  q=req(3,1,rows,5000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count<=16&&!q.lost_updates);u64 packets=0;for(u32 i=0;i<q.count;i++)packets+=rows[i].rx_packets+rows[i].tx_packets;T(packets==q.sequence);
 }
 for(unsigned i=0;i<8;i++){assert(!pthread_join(threads[i],NULL));}q=req(3,1,rows,5000);T(!io(GTA3XLWIFI_STATS_READ,&q)&&q.count==16&&q.sequence==80000&&!q.lost_updates&&allocs==frees);
 T(!state().pending_mask&&state().active_epoch==1);printf("active_cases=%u total_cases=%u concurrent_active_updates=80000\n",cases-begin,cases);return 0;
}
'''
shutil.copytree(R/'include',O/'include');header=S/'include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h';shutil.copyfile(header,O/'include/linux/netfilter'/header.name);(O/'test.c').write_text(code)
cmd=[v.replace(str(R),str(O)) for v in r['command']];x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=240,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.search(r'active_cases=(\d+) total_cases=(\d+) concurrent_active_updates=80000\n$',x.stdout);assert match
paths=[Path(__file__),h,new,old,header,R/'report.json',R/'test.c',O/'test.c',*(O/'include').rglob('*.h')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'active_cases':int(match[1]),'passed_cases':int(match[2]),'actual_A17_GSO_comparisons':9830400,'concurrent_storage_updates':80000,'concurrent_active_updates':80000,'no_swap_ack_or_counter_changes':True,'packet_and_other_control_source_unchanged':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
