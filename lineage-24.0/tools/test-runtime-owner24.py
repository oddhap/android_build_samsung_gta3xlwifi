#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual five-state owner and runtime SET/readback with full prior failure fixtures.

All legacy successful fixtures explicitly choose flags7; production State has
no implicit configuration. Runtime kernel wire/state, RCU and packets are fixtures
here; the separate actual kernel/pinned A17 predicate test establishes modes.
"""
import argparse,ast,hashlib,importlib.util,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','transport-report','generic-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==1537 and sha(R/'test.cpp')==r['inputs_sha256'][str(R/'test.cpp')]
t=json.loads(a.transport_report.read_text());assert t['passed'] and t['passed_cases']>=71
for name in ['Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiNetpolicyLease.h','gta3xlwifi_runtime_policy.h']:
 path=S/name if not name.endswith('policy.h') else S/'linux/netfilter'/name
 assert sha(path)==next(v for k,v in t['inputs_sha256'].items() if Path(k).name==name)
G=a.generic_host.resolve();g=json.loads((G/'report.json').read_text());assert g['passed'] and g['passed_cases']==994 and sha(G/'test.cpp')==g['inputs_sha256'][str(G/'test.cpp')]
extractor=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');sp=importlib.util.spec_from_file_location('extract',extractor);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
generic=m.extract((G/'test.cpp').read_text(),'main').replace('int main(', 'static int generic_runtime_regressions(',1).replace('features=1023','features=17407')
last=generic.rfind('}');generic=generic[:last]+'return 0;'+generic[last:]
shutil.copyfile(R/'IptablesRestoreController.h',O/'IptablesRestoreController.h');code=(R/'test.cpp').read_text();code='static void resetRuntimeFixture();\n'+code
code=code.replace('extern "C" int __wrap_ioctl(', 'extern "C" int underlyingIoctl(',1).replace('int __wrap_close(', 'int underlyingClose(',1).replace('int __wrap_open(', 'int underlyingOpen(',1)
code=code.replace('features=1023','features=17407').replace('features=16383','features=32767').replace('bit<14','bit<15')
code=code.replace('firewallAllowed=true;}\nP::State desired','firewallAllowed=true;resetRuntimeFixture();}\nP::State desired',1)
code=code.replace('P::State s;assert(s.policy.setChainEnabled','P::State s;s.runtime={true,7,{}};assert(s.policy.setChainEnabled',1)
code=code.replace('int main(){','static int baseline_runtime_regressions(){',1)
code=code.replace('assert(t->version==1&&t->count<=65536&&bool(t->count)==bool(t->entries));','if(!(t->version==1&&t->count<=65536&&bool(t->count)==bool(t->entries))){fprintf(stderr,"bad UID payload cmd=%lx version=%u count=%u ptr=%llu\\n",cmd,t->version,t->count,(unsigned long long)t->entries);}assert(t->version==1&&t->count<=65536&&bool(t->count)==bool(t->entries));')
helper=Path(__file__).with_name('test-runtime-transport24.py');tree=ast.parse(helper.read_text());fragment=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.AugAssign) and isinstance(n.target,ast.Name) and n.target.id=='code')
fragment=fragment[:fragment.index('int main(){')]
fragment=fragment.replace('static void resetRuntime(){resetEvents();features=16384;','static void resetRuntimeFixture(){')
fragment=fragment.replace('assert(files.count(fd)&&arg);auto*t=', 'assert(files.count(fd)&&arg);bool bad=point();if(bad&&!ioAfter){errno=EIO;return -1;}auto*t=',1)
fragment=fragment.replace('if(cmd==GTA3XLWIFI_RUNTIME_SET){++sets;', 'if(cmd==GTA3XLWIFI_RUNTIME_SET){firewallAllowed=false;++sets;',1)
fragment=fragment.replace('return positiveSet?1:-1;}return 0;', 'return positiveSet?1:-1;}if(bad){errno=EIO;return -1;}return 0;',1)
fragment=fragment.replace('return positiveGet?1:-1;}return 0;', 'return positiveGet?1:-1;}if(bad){errno=EIO;return -1;}return 0;',1)
# actual variable names in the bound fragment are runtimeGetError/runtimeSetError.
assert 'bool bad=point()' in fragment and fragment.count('if(bad){errno=EIO;return -1;}')==2
code+='\n'+generic+'\n'+fragment+r'''
int main(){
 C(generic_runtime_regressions()==0);C(baseline_runtime_regressions()==0);unsigned before=cases;
 resetApi();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);P::State unset;auto count=ioCount;C(p.replace(unset,0)==-EINVAL&&ioCount==count&&held);auto value=desired();value.runtime.flags=8;C(p.replace(value,0)==-EINVAL&&ioCount==count&&held);value=desired();value.runtime.legacyBlockedUids={2,1};C(p.replace(value,0)==-EINVAL&&ioCount==count&&held);value=desired();value.runtime.legacyBlockedUids={UINT32_MAX};C(p.replace(value,0)==-EINVAL&&ioCount==count&&held);C(p.replace(desired(),0)==0&&!held&&runtimeImage.confirmedForLease&&runtimeImage.flags==7);C(p.setRuntimePolicy(0,{10001,110001})==0&&!held&&runtimeImage.flags==0&&runtimeImage.legacyBlockedUids==std::vector<uint32_t>({10001,110001}));P::State out;uint64_t generation=0;C(!p.snapshot(&out,&generation)&&out.runtime.supplied&&out.runtime.flags==0&&out.runtime.legacyBlockedUids==runtimeImage.legacyBlockedUids);C(p.removeUid(10001)==0&&runtimeImage.legacyBlockedUids==std::vector<uint32_t>{110001});count=ioCount;C(p.setRuntimePolicy(8,{})==-EINVAL&&p.setRuntimePolicy(0,{2,1})==-EINVAL&&ioCount==count&&!held);}
 for(unsigned flags=0;flags<8;flags++){resetApi();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);auto s=desired();s.runtime={true,flags,{10001}};C(p.replace(s,0)==0&&!held&&runtimeImage.flags==flags&&runtimeImage.confirmedForLease);C(p.setDataSaver(false)==0&&runtimeImage.flags==flags&&!held);}
 for(unsigned fault:{1u,4u,5u,6u}){resetApi();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);metaFault=fault;C(p.setDataSaver(false)<0&&held&&files.empty()&&!runtimeImage.confirmedForLease);P::State out;uint64_t g=77;C(p.snapshot(&out,&g)==-EAGAIN&&g==77);}
 resetApi();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);runtimeImage.flags=0;C(p.setDataSaver(false)==-EUCLEAN&&held&&files.empty());}
 resetApi();{AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0&&p.replace(desired(),0)==0);runtimeImage.confirmedForLease=false;C(p.setDataSaver(false)==-EUCLEAN&&held&&files.empty());}
 for(bool loop:{false,true}){resetApi();AccountingCombined k;P p(k);C(p.startWithAccounting(accountingProgram)==0);auto policy=desired();policy.permissions=android::net::gta3xlwifi::UidPermissionState{};android::net::gta3xlwifi::PermissionBootstrap::Snapshot f;f.users={0};f.knownUids={10001,10002};f.observed={{0,1023},{1000,1023},{10001,4}};f.loopbackPermissionEnabled=loop;C(p.publishInitialPermissions(policy,f)==0&&!held&&runtimeImage.confirmedForLease);P::State out;uint64_t g;uint32_t mask;C(!p.snapshot(&out,&g)&&!out.permissions.get(10002,&mask)&&mask==4&&out.runtime.flags==7);}
 C(files.empty()&&held);printf("runtime_owner_cases=%u total_cases=%u\n",cases-before,cases);return 0;
}
''';(O/'test.cpp').write_text(code);names=['Gta3xlwifiNetpolicyLease','Gta3xlwifiCheckedUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiSocketRoots','Gta3xlwifiIngressPolicy','Gta3xlwifiMeteredChainProgram','Gta3xlwifiMeteredRoots','Gta3xlwifiUidPermissionState','Gta3xlwifiLocalNetworkState','Gta3xlwifiSocketPolicyProjection','Gta3xlwifiAccountingRoots','Gta3xlwifiPermissionBootstrap'];sources=[S/(n+'.cpp') for n in names];cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-Wno-unused-function','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+n for n in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=180,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);match=re.fullmatch(r'passed_cases=(\d+) start_fault_points=(\d+) replace_fault_points=(\d+)\npassed_cases=(\d+) start_fault_points=(\d+) replace_fault_points=(\d+)\nowner_api_cases=(\d+) total_cases=(\d+)\nruntime_owner_cases=(\d+) total_cases=(\d+)\n',x.stdout);assert match and int(match[2])>28 and int(match[3])>102 and int(match[5])>74 and int(match[6])>114
paths=[Path(__file__),helper,extractor,G/'report.json',G/'test.cpp',R/'report.json',R/'test.cpp',a.transport_report,O/'test.cpp',O/'IptablesRestoreController.h',S/'projection-guards.inc',*sources,*[p.with_suffix('.h') for p in sources],*[p for p in (S/'linux/netfilter').glob('*.h')]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[10]),'generic_regression_cases':int(match[1]),'generic_start_fault_points':int(match[2]),'generic_replace_fault_points':int(match[3]),'start_fault_points':int(match[5]),'replace_fault_points':int(match[6]),'one_lease_four_state_publication':True,'five_state_runtime_publication':True,'hard_no_firewall_after_first_image_set':True,'runtime_before_LNA_and_UID_last':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
