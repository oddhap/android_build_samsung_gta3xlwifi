#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual sole-owner DNS reader/registry/wrappers/proxy branches with fault fixtures.

Replays the complete prior owner/service regression. Android Result/property/BPF
and ioctl/rule effects are explicit host fixtures. Native DSO linking is separate.
"""
import argparse,fcntl,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['top','source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();T=a.top.resolve();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();r=json.loads((R/'report.json').read_text());assert r['passed'] and r['passed_cases']==25856 and sha(R/'test.cpp')==r['inputs_sha256'][str(R/'test.cpp')]
def extract(text,signature):
 start=text.index(signature);body=text.index('{',start);depth=1;i=body+1
 while depth:depth+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[start:i]
helper=(S/'DnsBpfHelper.cpp').read_text();proxy=(S/'DnsProxyListener.cpp').read_text();provider=(S/'Gta3xlwifiHeldProvider.cpp').read_text()
branch='if (base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false))'
init=extract(extract(helper,'base::Result<void> DnsBpfHelper::init()'),branch)
query=extract(extract(helper,'base::Result<bool> DnsBpfHelper::isUidNetworkingBlocked('),branch)
setter=extract(helper,'extern "C" int ADnsHelper_setLegacyCallbackV2(')
wrapper=extract(proxy,'extern "C" int resolv_set_gta3xlwifi_policy(')
proxy_fn=extract(proxy,'bool isUidNetworkingBlocked(uid_t uid, unsigned netId)')
public=T/'packages/modules/Connectivity/bpf/dns_helper/DnsHelper.cpp';public_text=public.read_text();public_init=extract(public_text,'int ADnsHelper_init()');public_query=extract(public_text,'int ADnsHelper_isUidNetworkingBlocked(')
blocked=extract(provider,'int blocked(uid_t uid, bool metered)')
for name in ['IptablesRestoreController.h','binder','com']:
 if (R/name).is_dir():shutil.copytree(R/name,O/name)
 else:shutil.copyfile(R/name,O/name)
code=(R/'test.cpp').read_text().replace('int main(){','static int previous_owner_regressions(){',1)
code+=r'''
#include "LegacyDnsPolicy.h"
#include <atomic>
#include <memory>
static bool dnsLegacy=true,dnsMetered=false,dnsEnforce=false;static int dnsExperiment=1,stockInitCalls=0,stockReads=0;
namespace android::base{
static bool GetBoolProperty(const char*,bool){return dnsLegacy;}
class Error{int mCode;public:explicit Error(int code):mCode(code){}int code()const{return mCode;}template<class T>Error&operator<<(const T&){return *this;}};
template<class T>class Result{bool mOk=true;T mValue{};Error mError{0};public:Result(T value):mValue(value){}Result(const Error&e):mOk(false),mError(e){}bool ok()const{return mOk;}const Error&error()const{return mError;}T value()const{return mValue;}};
template<>class Result<void>{bool mOk=true;Error mError{0};public:Result()=default;Result(const Error&e):mOk(false),mError(e){}bool ok()const{return mOk;}const Error&error()const{return mError;}};
}
namespace android::net{
static LegacyDnsPolicy sLegacyDnsPolicy;
class DnsHelperFixture{public:base::Result<void>init(){
'''+init+r'''
++stockInitCalls;return {};}
base::Result<bool>isUidNetworkingBlocked(uid_t uid,bool metered){
'''+query+r'''
++stockReads;return false;}};
}
static android::net::DnsHelperFixture sDnsBpfHelper;
'''+public_init+'\n'+public_query+'\n'+setter+'\n'+wrapper+r'''
namespace DnsAdapter{P* owner=nullptr;
'''+blocked+r'''
}
namespace ProxyFixture{
static bool isAtLeastT(){return true;}
static bool resolv_is_enforceDnsUid_enabled_network(unsigned){return dnsEnforce;}
static bool resolv_is_metered_network(unsigned){return dnsMetered;}
struct Experiments{static Experiments*getInstance(){static Experiments e;return &e;}int getFlag(const char*,int){return dnsExperiment;}};
'''+proxy_fn+r'''
}
static int malformed(uid_t uid,bool){return uid==0?2:uid==1?INT_MIN:-4096;}
static int alternate(uid_t,bool){return 0;}
static void resetDns(){std::destroy_at(&android::net::sLegacyDnsPolicy);std::construct_at(&android::net::sLegacyDnsPolicy);dnsLegacy=true;dnsMetered=false;dnsEnforce=false;dnsExperiment=1;stockInitCalls=stockReads=0;}
int main(){C(previous_owner_regressions()==0);allowHeldActive=true;unsigned begin=cases;
 // The preflight and daemon use distinct owners but the SAME retained rule
 // images/kernel state. No fixture reset between the two lifetimes.
 resetActive();{AccountingCombined kernel;
  {P preflight(kernel);C(!preflight.startWithAccounting(accountingProgram));C(!preflight.verifyHeldProviderStartup());C(held);preflight.stop();C(held&&files.empty());}
  {P daemon(kernel);C(!daemon.startWithAccounting(accountingProgram));C(!daemon.verifyHeldProviderStartup());C(held);C(!daemon.replace(desired(),0));C(!held);daemon.stop();C(held&&files.empty());}
 }

 resetActive();resetDns();{AccountingCombined kernel;P owner(kernel);DnsAdapter::owner=&owner;C(owner.isNetworkingBlocked(10001,false)==-EAGAIN);C(owner.isNetworkingBlocked(-1,false)==-EINVAL);C(!owner.startWithAccounting(accountingProgram));C(!owner.verifyHeldProviderStartup());C(ADnsHelper_init()==-ENOTCONN&&stockInitCalls==0);C(resolv_set_gta3xlwifi_policy(nullptr)==-EINVAL);C(resolv_set_gta3xlwifi_policy(DnsAdapter::blocked)==0);C(resolv_set_gta3xlwifi_policy(DnsAdapter::blocked)==0);C(resolv_set_gta3xlwifi_policy(alternate)==-EALREADY);C(ADnsHelper_init()==0&&held&&stockInitCalls==0);C(ADnsHelper_isUidNetworkingBlocked(10001,false)==-EAGAIN);C(ProxyFixture::isUidNetworkingBlocked(10001,1));C(ADnsHelper_isUidNetworkingBlocked(UINT_MAX,false)==-EINVAL);C(ProxyFixture::isUidNetworkingBlocked(UINT_MAX,1));C(!owner.replace(desired(),0));
 for(bool metered:{false,true})for(int uid:{0,1000,10001,10002,1010001,INT_MAX}){P::State state;uint64_t generation;C(!owner.snapshot(&state,&generation));int expected=state.policy.isNetworkingBlocked(uid,metered);C(ADnsHelper_isUidNetworkingBlocked(uid,metered)==expected);dnsMetered=metered;C(ProxyFixture::isUidNetworkingBlocked(uid,1)==(expected==1));}
 for(unsigned n=0;n<20;++n){C(!owner.setDataSaver(n%2));for(bool metered:{false,true}){P::State state;uint64_t g;C(!owner.snapshot(&state,&g));C(ADnsHelper_isUidNetworkingBlocked(10002,metered)==state.policy.isNetworkingBlocked(10002,metered));}}
 std::atomic<unsigned>reads{0},bad{0};std::thread reader([&]{for(unsigned n=0;n<200;n++){int r=ADnsHelper_isUidNetworkingBlocked(10001,true);if(r!=0&&r!=1)++bad;++reads;}});for(unsigned n=0;n<10;n++)C(!owner.setDataSaver(n%2));reader.join();C(reads==200&&bad==0);
 C(!owner.suspendFrameworkClient()&&held);C(ADnsHelper_isUidNetworkingBlocked(0,false)==-EAGAIN);C(ProxyFixture::isUidNetworkingBlocked(10001,1));dnsExperiment=0;C(!ProxyFixture::isUidNetworkingBlocked(10001,1)&&held);dnsExperiment=1;dnsEnforce=true;C(!ProxyFixture::isUidNetworkingBlocked(10001,1)&&held);dnsEnforce=false;C(stockReads==0&&stockInitCalls==0);C(!owner.replace(desired(),0));ioCount=0;ioFault=1;ioAfter=false;C(owner.setDataSaver(true)<0&&held&&files.empty());C(ADnsHelper_isUidNetworkingBlocked(10001,false)==-EAGAIN&&ProxyFixture::isUidNetworkingBlocked(10001,1));DnsAdapter::owner=nullptr;C(ADnsHelper_isUidNetworkingBlocked(10001,false)==-ENOTCONN);}
 resetDns();C(resolv_set_gta3xlwifi_policy(malformed)==0);for(uid_t uid:{0u,1u,2u}){C(ADnsHelper_isUidNetworkingBlocked(uid,false)==-EPROTO);C(ProxyFixture::isUidNetworkingBlocked(uid,1));}dnsLegacy=false;C(resolv_set_gta3xlwifi_policy(alternate)==-EOPNOTSUPP);C(ADnsHelper_init()==0&&stockInitCalls==1);C(!ProxyFixture::isUidNetworkingBlocked(10001,1)&&stockReads==1);C(files.empty()&&held);
 printf("dns_owner_cases=%u prior_plus_new_cases=%u concurrent_reads=%u\n",cases-begin,cases,200u);return 0;
}
'''
(O/'test.cpp').write_text(code);old_source=next(Path(v).parent for v in r['command'] if v.endswith('/Gta3xlwifiSocketPolicyProjection.cpp'));cmd=[v.replace(str(R),str(O)).replace(str(old_source),str(S)) for v in r['command']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-12000:]
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=300,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);m=re.search(r'dns_owner_cases=(\d+) prior_plus_new_cases=(\d+) concurrent_reads=200\n$',x.stdout);assert m
paths=[Path(__file__),R/'report.json',R/'test.cpp',S/'DnsBpfHelper.cpp',S/'DnsProxyListener.cpp',S/'Gta3xlwifiHeldProvider.cpp',S/'LegacyDnsPolicy.h',public,O/'test.cpp',*[Path(v) for v in cmd if v.startswith(str(S)) and v.endswith('.cpp')],*S.glob('Gta3xlwifi*.h')]
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[2]),'new_DNS_and_retained_restart_cases':int(m[1]),'distinct_preflight_daemon_owners_same_retained_kernel_images':True,'concurrent_DNS_reads':200,'prior_25856_owner_cases_replayed':True,'unpublished_failed_and_malformed_policy_blocks':True,'upstream_OEM_experiment_controls_preserved':True,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
