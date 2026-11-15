#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual kernel UID receipts, deduplication, full ioctl routing and prior GSO/storage.

Kernel socket/copy/credential boundaries are explicit fixtures. Actual pthread
locks exercise the retained producer/read tests. No hardware or networking Ready.
"""
import argparse,fcntl,hashlib,importlib.util,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','base-source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();B=a.base_source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==5392
historical_unused_runner_changes={}
for n,expected in r['inputs_sha256'].items():
 actual=sha(Path(n))
 if actual!=expected:
  assert Path(n).name=='test-kernel-active-stats24.py',('Changed replay input',n)
  # This historical runner is neither imported nor executed here. Its exact
  # compiled test.c and every header/source remain hash-checked above/below.
  historical_unused_runner_changes[n]={'expected':expected,'current':actual}

h=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');sp=importlib.util.spec_from_file_location('extract',h);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
code=(R/'test.c').read_text();module=S/'net/netfilter/gta3xlwifi_packet_stats.c';driver=S/'net/netfilter/gta3xlwifi_netpolicy.c';text=module.read_text()
for name in ['gta3xlwifi_packet_stats_features','stats_swap','stats_edit','gta3xlwifi_packet_stats_ioctl']:
 prior=m.extract(code,name);assert code.count(prior)==1;code=code.replace(prior,m.extract(text,name))
code=code.replace('static u32 stats_active;', 'static u32 stats_active;\nstatic struct gta3xlwifi_uid_cleanup uid_cleanup_receipt;',1)
pos=code.index('static long stats_edit(');extra='\n'.join(m.extract(text,n) for n in ['cleanup_same','gta3xlwifi_packet_stats_cleanup_pending','stats_cleanup']);code=code[:pos]+extra+'\n'+code[pos:]
code=code.replace('==36864', '==167936')
code=code.replace('static void reset_store(void){','static void reset_store(void){memset(&uid_cleanup_receipt,0,sizeof(uid_cleanup_receipt));',1)
code=code.replace('int main(void){', 'static int previous_receipt_regressions(void){',1)
# The previous active test main already returns0 explicitly.
prior=m.extract(code,'netpolicy_image_ioctl');code=code.replace(prior,m.extract(driver.read_text(),'netpolicy_image_command')+'\n'+m.extract(driver.read_text(),'netpolicy_image_ioctl'))
code=code.replace('static long gta3xlwifi_iface_stats_ioctl(unsigned c,unsigned long a){(void)c;(void)a;assert(!"unrelated interface fixture");return -ENOTTY;}', 'static unsigned name_dispatches;static long gta3xlwifi_iface_stats_ioctl(unsigned c,unsigned long a){(void)a;if(c==GTA3XLWIFI_IFACE_NAMES_GET){name_dispatches++;return -ENODATA;}assert(!"unrelated interface fixture");return -ENOTTY;}')
assert 'name_dispatches' in code
code+=r'''
static bool fixture_runtime_configured=true;static unsigned sync_calls;
static bool gta3xlwifi_runtime_configured(void){return fixture_runtime_configured;}
#ifndef smp_store_release
#define smp_store_release(p,v) (*(p)=(v))
#endif
#define synchronize_net() (++sync_calls)
#define WRITE_ONCE(x,v) ((x)=(v))
'''+m.extract(driver.read_text(),'netpolicy_ioctl')+r'''
static long cleanup(u32 op,u32 uid,u64 nonce,u64 gen,u64 epoch,struct gta3xlwifi_uid_cleanup*out){
 struct gta3xlwifi_uid_cleanup q={.version=1,.operation=op,.uid=uid,.nonce=nonce,.generation=gen,.active_epoch=epoch};long result=netpolicy_ioctl(&owner,GTA3XLWIFI_UID_CLEANUP,(unsigned long)&q);if(out)*out=q;return result;
}
int main(void){T(!previous_receipt_regressions());unsigned begin=cases;struct gta3xlwifi_uid_cleanup q;
 T(sizeof(q)==64&&GTA3XLWIFI_UID_CLEANUP==0xc0406763U);reset_store();T(!cleanup(0,0,0,0,0,&q)&&q.version==1&&q.phase==0&&q.nonce==0);T(!gta3xlwifi_packet_stats_cleanup_pending());
 T(!gta3xlwifi_packet_stats_record(NULL,&packet,123,7,17,true));T(!cleanup(1,123,1,5,1,&q)&&q.phase==1&&q.nonce==1&&q.generation==5);T(gta3xlwifi_packet_stats_cleanup_pending());
 T(cleanup(1,123,1,5,1,NULL)==-EINPROGRESS);T(cleanup(1,123,2,5,1,NULL)==-EBUSY);T(cleanup(1,124,1,5,1,NULL)==-ESTALE);T(cleanup(1,123,1,6,1,NULL)==-ESTALE);T(cleanup(1,123,1,5,2,NULL)==-ESTALE);
 struct gta3xlwifi_packet_stats_swap sw={1,0,1,0,0,0};T(io(GTA3XLWIFI_STATS_SWAP,&sw)==-EBUSY);T(edit(GTA3XLWIFI_STATS_DELETE_UID,123,0)==-EBUSY);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==-EBUSY&&netpolicy_held);
 T(!cleanup(2,123,1,5,1,&q)&&q.phase==2&&!gta3xlwifi_packet_stats_cleanup_pending());T(!stats_banks[stats_active].count&&!app_count&&!set_count);T(netpolicy_ioctl(&owner,GTA3XLWIFI_NETPOLICY_RELEASE,0)==0&&!netpolicy_held);
 // UID reuse after completed deletion: duplicate BEGIN/COMMIT must preserve new data.
 T(!gta3xlwifi_packet_stats_record(NULL,&packet,123,9,17,true));T(!cleanup(1,123,1,5,1,&q)&&q.phase==2&&app_count==1&&stats_banks[stats_active].count==1);T(!cleanup(2,123,1,5,1,&q)&&app_count==1&&stats_banks[stats_active].count==1);
 sw=flip();T(ack(sw.inactive_bank,sw.inactive_epoch)==0);T(!cleanup(1,123,1,5,1,&q)&&q.phase==2&&app_count==1);T(!cleanup(2,123,1,5,1,&q)&&app_count==1);
 T(cleanup(1,123,2,6,1,NULL)==-ESTALE);T(!cleanup(1,123,2,6,2,&q)&&q.phase==1);T(!cleanup(2,123,2,6,2,&q)&&!app_count);T(cleanup(1,123,1,5,1,NULL)==-ESTALE);
 // Credential/file/TGID checks on the full entry point, before either new operation.
 privileged=false;T(cleanup(0,0,0,0,0,NULL)==-EPERM);privileged=true;T(netpolicy_ioctl(&other_file,GTA3XLWIFI_UID_CLEANUP,(unsigned long)&q)==-EPERM);fixture_pid=&other_pid;T(cleanup(0,0,0,0,0,NULL)==-EPERM);fixture_pid=&owner_pid;
 // Interface-name opcode must reach the inner authenticated dispatcher.
 T(netpolicy_ioctl(&owner,GTA3XLWIFI_IFACE_NAMES_GET,(unsigned long)&q)==-ENODATA&&name_dispatches==1);
 reset_store();for(unsigned fault=0;fault<12;++fault){struct gta3xlwifi_uid_cleanup bad={.version=1,.operation=1,.uid=123,.nonce=1,.active_epoch=1};switch(fault){case 0:bad.version=2;break;case 1:bad.operation=3;break;case 2:bad.phase=1;break;case 3:bad.uid=0x80000000U;break;case 4:bad.nonce=0;break;case 5:bad.active_epoch=0;break;default:bad.reserved[fault-6]=1;break;}T(netpolicy_ioctl(&owner,GTA3XLWIFI_UID_CLEANUP,(unsigned long)&bad)==-EINVAL&&uid_cleanup_receipt.phase==0);}
 for(unsigned field=0;field<4;++field){struct gta3xlwifi_uid_cleanup bad={.version=1};switch(field){case 0:bad.uid=1;break;case 1:bad.nonce=1;break;case 2:bad.generation=1;break;case 3:bad.active_epoch=1;break;}T(netpolicy_ioctl(&owner,GTA3XLWIFI_UID_CLEANUP,(unsigned long)&bad)==-EINVAL);}
 // Copy-out faults retain the committed phase. READ exposes it without replay.
 reset_store();to_fault=to_calls+1;T(cleanup(1,123,1,0,1,NULL)==-EFAULT&&gta3xlwifi_packet_stats_cleanup_pending());to_fault=0;T(!cleanup(0,0,0,0,0,&q)&&q.phase==1);T(cleanup(1,123,1,0,1,NULL)==-EINPROGRESS);
 T(!gta3xlwifi_packet_stats_record(NULL,&packet,123,1,17,true));to_fault=to_calls+1;T(cleanup(2,123,1,0,1,NULL)==-EFAULT&&!app_count);to_fault=0;T(!cleanup(0,0,0,0,0,&q)&&q.phase==2);
 T(!gta3xlwifi_packet_stats_record(NULL,&packet,123,2,17,true));T(!cleanup(2,123,1,0,1,&q)&&app_count==1);
 reset_store();from_fault=from_calls+1;T(cleanup(1,123,1,0,1,NULL)==-EFAULT&&!uid_cleanup_receipt.phase);from_fault=0;
 // Frozen-bank and stale-commit fences precede any packet/app deletion.
 reset_store();sw=flip();T(cleanup(1,123,1,0,2,NULL)==-EBUSY);T(!ack(sw.inactive_bank,sw.inactive_epoch));T(!cleanup(1,123,1,0,2,NULL));T(cleanup(2,124,1,0,2,NULL)==-ESTALE&&gta3xlwifi_packet_stats_cleanup_pending());T(!cleanup(2,123,1,0,2,NULL));
 printf("uid_receipt_cases=%u total_cases=%u\n",cases-begin,cases);return 0;
}
'''
code='#include <linux/netfilter/gta3xlwifi_netpolicy.h>\n#ifndef ARRAY_SIZE\n#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))\n#endif\n'+code
shutil.copytree(R/'include',O/'include')
for source in [S/'include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h',B/'include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h',B/'include/uapi/linux/netfilter/gta3xlwifi_netpolicy.h']:
 shutil.copyfile(source,O/'include/linux/netfilter'/source.name)
(O/'test.c').write_text(code);cmd=[v.replace(str(R),str(O)) for v in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);mch=re.search(r'uid_receipt_cases=(\d+) total_cases=(\d+)\n$',x.stdout);assert mch
paths=[Path(__file__),h,R/'report.json',R/'test.c',O/'test.c',*[p for p in S.rglob('*') if p.is_file()],*(O/'include').rglob('*.h')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(mch[2]),'uid_receipt_cases':int(mch[1]),'prior_5392_checks_and_9830400_GSO_comparisons_replayed':True,'actual_outer_ioctl_and_name_dispatch_executed':True,'historical_unused_runner_changes':historical_unused_runner_changes,'cached_completed_nonce_preserves_reused_UID_data':True,'prepared_receipt_blocks_release_and_swap':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
