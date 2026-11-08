#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real canonical LNA/UID/rules publication and retained-state mutators, host I/O.

No Binder/global networking readiness or kernel packet execution. Values become
visible only after complete modeled real-transport readback and gate release.
"""
import argparse,ast,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-local-network-transport24.py');subprocess.run(['python3',str(helper),'--source',str(S),'--output',str(O/'transport-regression')],check=True)
old=Path(__file__).with_name('test-uid-permission-publication24.py');subprocess.run(['python3',str(old),'--source',str(S),'--output',str(O/'uid-publication-regression')],check=True)
code=(O/'transport-regression/test.cpp').read_text().split('int main(){',1)[0]
code=code.replace('unsigned cases=0;','unsigned cases=0;bool firewallAllowed=true;').replace('++opens;held=true;','++opens;held=true;firewallAllowed=true;').replace('held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;','if(cmd==GTA3XLWIFI_NETPOLICY_HOLD){firewallAllowed=true;}held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;').replace('&&held);++setCalls;','&&held);++setCalls;firewallAllowed=false;').replace('assert(held);++lnaSets;','assert(held);++lnaSets;firewallAllowed=false;').replace('void resetLna(){resetImage();','void resetLna(){firewallAllowed=true;resetImage();')
other=Path(__file__).with_name('test-owner-dispatch-transaction24.py');tree=ast.parse(other.read_text());extra=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.AugAssign) and isinstance(n.target,ast.Name) and n.target.id=='code');code+=extra.split('int main(){',1)[0].replace('&&held&&opens==1','&&firewallAllowed&&held&&opens==1')
header=next(ast.literal_eval(n.value.args[0]) for n in tree.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='write_text');(O/'IptablesRestoreController.h').write_text(header)
code+=r'''
UidPermissionState permissions(uint32_t mask=4){UidPermissionState p;assert(p.set(10001,mask)==0);return p;}
using LState=LocalNetworkState;using Table=LState::Table;
LEntry uidHost(unsigned uid,unsigned bits){LEntry e={bits,{},true};unsigned iface=17;memcpy(e.key.data(),&uid,4);memcpy(e.key.data()+4,&iface,4);e.key[8]=0xfd;return e;}
LState local(){LState s;assert(s.replace(network,{uidHost(10001,64),uidHost(10001,192),uidHost(10002,64)})==0);return s;}
LEntry query={192,{},false};
void unpublished(P&p){uint32_t mask=777;bool found=true,allowed=false;C(p.getUidPermission(10001,&mask)==-EAGAIN&&mask==777);C(p.getLocalNetworkAccess(Table::Network,query,&found,&allowed)==-EAGAIN&&found&&!allowed);C(p.isNetworkingBlocked(10001,false)==-EAGAIN);}
int main(){
 resetLna();{Kernel k;P p(k);unpublished(p);C(p.setLocalNetworkEntry(Table::Network,query)==-EAGAIN);C(p.removeLocalNetworkEntry(Table::Network,query)==-EAGAIN);C(p.replace(configured(),permissions(),local())==-ENOTCONN&&k.calls==0);
 C(p.start()==0&&held);C(p.replace(configured(),permissions(),local())==0&&!held&&lnaRevision==1&&kernelRevision==1);bool found=false,allowed=true;uint32_t mask=0;C(p.getLocalNetworkAccess(Table::Network,query,&found,&allowed)==0&&found&&!allowed);C(p.getUidPermission(10001,&mask)==0&&mask==4);
 auto allow=query;allow.allowed=true;C(p.setLocalNetworkEntry(Table::Network,allow)==0&&lnaRevision==2&&kernelRevision==2);C(p.getLocalNetworkAccess(Table::Network,query,&found,&allowed)==0&&found&&allowed);C(p.setUidPermission(10001,1)==0&&lnaRevision==3&&kernelRevision==3);C(p.getLocalNetworkAccess(Table::Network,query,&found,&allowed)==0&&found&&allowed);
 C(p.setDataSaver(false)==0&&lnaRevision==4&&kernelRevision==4);C(p.replace(configured())==0&&lnaRevision==5&&kernelRevision==5);C(p.replace(configured(),permissions())==0&&lnaRevision==6&&kernelRevision==6);C(p.getLocalNetworkAccess(Table::Network,query,&found,&allowed)==0&&found&&allowed);
 C(p.removeLocalNetworkEntry(Table::Network,query)==0&&lnaRevision==7&&kernelRevision==7);C(p.getLocalNetworkAccess(Table::Network,query,&found,&allowed)==0&&found&&!allowed);
 auto before=k.calls,io=lnaIoctls;LEntry bad={193,{},true};C(p.setLocalNetworkEntry(Table::Host,bad)==-EINVAL);C(p.removeLocalNetworkEntry(static_cast<Table>(2),query)==-EINVAL);C(k.calls==before&&lnaIoctls==io&&!held);C(p.getUidPermission(10001,&mask)==0&&mask==4);
 C(p.removeUid(10001)==0&&lnaRevision==8&&kernelRevision==8&&kernelImage.empty()&&hostImage.size()==1);C(p.getUidPermission(10001,&mask)==0&&mask==0);unsigned uid;memcpy(&uid,hostImage[0].key,4);C(uid==10002);p.stop();unpublished(p);}
 for(bool prior:{false,true})for(unsigned failure:{1u,2u})for(bool committed:{false,true}){
  resetLna();Kernel k;P p(k);C(p.start()==0);if(prior)C(p.replace(UidPolicy{},permissions(1),local())==0);auto oldTables=k.tables;auto oldNet=netImage,oldHost=hostImage;auto oldUid=kernelImage;k.writes=0;k.failWriteAt=failure;k.commitFailure=committed;C(p.replace(configured(),permissions(),local())==-EREMOTEIO&&held&&files.empty()&&k.tables==oldTables&&equalLWire(netImage,oldNet)&&equalLWire(hostImage,oldHost)&&equalWire(kernelImage,oldUid));unpublished(p);
 }
 for(bool commit:{false,true}){
  resetLna();Kernel k;P p(k);C(p.start()==0);lnaSetError=EIO;lnaCommitError=commit;C(p.replace(configured(),permissions(),local())==-EUCLEAN&&held&&files.empty());unpublished(p);lnaSetError=0;C(p.start()==0&&held);C(p.replace(configured(),permissions(1),local())==0&&!held);uint32_t mask=0;C(p.getUidPermission(10001,&mask)==0&&mask==1);
 }
 for(bool commit:{false,true}){
  resetLna();Kernel k;P p(k);C(p.start()==0);setError=EIO;commitThenError=commit;C(p.replace(configured(),permissions(),local())==-EUCLEAN&&held&&files.empty()&&lnaRevision==1);unpublished(p);
 }
 resetLna();{Kernel k;P p(k);C(p.start()==0&&p.replace(configured(),permissions(),local())==0);auto nextLocal=local();auto allow=query;allow.allowed=true;assert(nextLocal.set(Table::Network,allow)==0);auto nextPolicy=configured();assert(nextPolicy.setUidRule(1,10002,UidPolicy::Allow)==0);k.pause=true;int result=777;std::thread writer([&]{result=p.replace(nextPolicy,permissions(1),nextLocal);});{std::unique_lock<std::mutex> lock(k.gate);assert(k.cv.wait_for(lock,std::chrono::seconds(5),[&]{return k.blocked;}));}
 C(held&&kernelRevision==1&&lnaRevision==1&&kernelImage[0].permissions==4);std::atomic<bool> begun=false,done=false;bool found=false,allowed=false;int queryResult=777;std::thread reader([&]{begun=true;queryResult=p.getLocalNetworkAccess(Table::Network,query,&found,&allowed);done=true;});while(!begun.load())std::this_thread::yield();C(!done.load());{std::lock_guard<std::mutex> lock(k.gate);k.resume=true;k.cv.notify_all();}writer.join();reader.join();C(result==0&&queryResult==0&&found&&allowed&&done.load()&&!held&&kernelRevision==2&&lnaRevision==2);uint32_t mask=0;C(p.getUidPermission(10001,&mask)==0&&mask==1);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);names=['Gta3xlwifiCheckedUidChains','Gta3xlwifiNetpolicyLease','Gta3xlwifiDualStackUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiMeteredChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiUidPolicyTransaction','Gta3xlwifiUidPermissionState','Gta3xlwifiLocalNetworkState'];sources=[S/(n+'.cpp') for n in names];cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=80
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,old,other,O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[s.with_suffix('.h') for s in sources],*[S/'linux/netfilter'/n for n in ['gta3xlwifi_netpolicy.h','gta3xlwifi_uid_permissions.h','gta3xlwifi_local_network.h']]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':x.stderr,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'all_values_withdrawn_on_kernel_error':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual full LNA/UID/rules publication, fatal UBSan')
