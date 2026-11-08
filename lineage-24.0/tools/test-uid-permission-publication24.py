#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual combined UID value publication, real encoder/backend/lease, syscall fixtures.

No kernel/device/packet/Binder execution. Verifies values only become visible
after both-family rules and the real-transport modeled image verify and release;
uncertainty withdraws both values and holds the leased gate.
"""
import argparse,ast,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-uid-permission-transport24.py');subprocess.run(['python3',str(helper),'--source',str(S),'--output',str(O/'transport-regression')],check=True);code=(O/'transport-regression/test.cpp').read_text().split('int main(){',1)[0]
other=Path(__file__).with_name('test-owner-dispatch-transaction24.py');tree=ast.parse(other.read_text());extra=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.AugAssign) and isinstance(n.target,ast.Name) and n.target.id=='code');code+=extra.split('int main(){',1)[0]
header=next(ast.literal_eval(n.value.args[0]) for n in tree.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='write_text');(O/'IptablesRestoreController.h').write_text(header)
code+=r'''
UidPermissionState permissions(uint32_t mask=4){UidPermissionState p;assert(p.set(10001,mask)==0);return p;}
int main(){
 resetImage();{Kernel k;P p(k);uint32_t mask=777;C(p.getUidPermission(10001,&mask)==-EAGAIN&&mask==777);C(p.setUidPermission(10001,4)==-EAGAIN);C(p.replace(configured(),permissions())==-ENOTCONN&&k.calls==0);
 C(p.start()==0&&held);C(p.replace(configured(),permissions())==0&&!held&&kernelRevision==1);C(p.getUidPermission(10001,&mask)==0&&mask==4);C(p.getUidPermission(10001,nullptr)==-EINVAL);
 C(p.setUidPermission(10001,1)==0&&kernelRevision==2&&!held);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 C(p.setDataSaver(false)==0&&kernelRevision==3);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 C(p.replace(configured())==0&&kernelRevision==4);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 auto calls=k.calls;auto io=imageIoctls;C(p.setUidPermission(-1,1)==-EINVAL);C(p.setUidPermission(10001,128)==-EINVAL);C(k.calls==calls&&imageIoctls==io);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 UidPermissionState huge;for(int i=0;i<65537;i++)assert(huge.set(i,1)==0);C(p.replace(configured(),huge)==-E2BIG&&k.calls==calls&&imageIoctls==io);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 C(p.setUidPermission(10001,0)==0&&kernelImage.empty());C(p.getUidPermission(10001,&mask)==0&&mask==0);
 C(p.setUidPermission(10001,4)==0);C(p.removeUid(10001)==0&&kernelImage.empty());C(p.getUidPermission(10001,&mask)==0&&mask==0);int32_t rule=777;C(p.getUidRule(1,10001,&rule)==0&&rule==UidPolicy::Deny);
 p.stop();mask=777;C(p.getUidPermission(10001,&mask)==-EAGAIN&&mask==777&&held&&files.empty());}
 for(bool prior:{false,true})for(auto failure:{1u,2u})for(bool committed:{false,true}){
  resetImage();Kernel k;P p(k);C(p.start()==0);if(prior)C(p.replace(UidPolicy{},permissions(1))==0);auto old=k.tables;auto oldImage=kernelImage;k.writes=0;k.failWriteAt=failure;k.commitFailure=committed;
  C(p.replace(configured(),permissions())==-EREMOTEIO&&held&&files.empty()&&k.tables==old&&equalWire(kernelImage,oldImage));uint32_t mask=777;bool enabled=true;
  C(p.getUidPermission(10001,&mask)==-EAGAIN&&mask==777);C(p.getChainEnabled(1,&enabled)==-EAGAIN&&enabled);
 }
 for(bool commit:{false,true}){
  resetImage();Kernel k;P p(k);C(p.start()==0);setError=EIO;commitThenError=commit;C(p.replace(configured(),permissions())==-EUCLEAN&&held&&files.empty());uint32_t mask=777;C(p.getUidPermission(10001,&mask)==-EAGAIN&&mask==777);C(p.isNetworkingBlocked(10001,false)==-EAGAIN);
  setError=0;C(p.start()==0&&held);C(p.replace(configured(),permissions(1))==0&&!held);C(p.getUidPermission(10001,&mask)==0&&mask==1);
 }
 resetImage();{Kernel k;P p(k);C(p.start()==0&&p.replace(configured(),permissions())==0);auto next=configured();assert(next.setUidRule(1,10002,UidPolicy::Allow)==0);k.pause=true;int result=777;std::thread writer([&]{result=p.replace(next,permissions(1));});{std::unique_lock<std::mutex> lock(k.gate);k.cv.wait(lock,[&]{return k.blocked;});}
 C(held&&kernelImage[0].permissions==4);std::atomic<bool> begun=false,done=false;uint32_t value=777;int query=777;std::thread reader([&]{begun=true;query=p.getUidPermission(10001,&value);done=true;});while(!begun.load())std::this_thread::yield();C(!done.load());{std::lock_guard<std::mutex> lock(k.gate);k.resume=true;k.cv.notify_all();}writer.join();reader.join();C(result==0&&query==0&&value==1&&!held&&done.load());C(p.isNetworkingBlocked(10002,false)==0);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);names=['Gta3xlwifiCheckedUidChains','Gta3xlwifiNetpolicyLease','Gta3xlwifiDualStackUidChains','Gta3xlwifiUidPolicy','Gta3xlwifiUidChainProgram','Gta3xlwifiMeteredChainProgram','Gta3xlwifiOrdinaryDispatch','Gta3xlwifiUidPolicyTransaction','Gta3xlwifiUidPermissionState'];sources=[S/(n+'.cpp') for n in names]
if (S/'Gta3xlwifiLocalNetworkState.cpp').exists():sources.append(S/'Gta3xlwifiLocalNetworkState.cpp')
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=60
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,other,O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[s.with_suffix('.h') for s in sources],S/'linux/netfilter/gta3xlwifi_netpolicy.h',S/'linux/netfilter/gta3xlwifi_uid_permissions.h'];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':x.stderr,'command':cmd,'inputs_sha256':{str(p.resolve()):sha(p) for p in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual combined permission/rule publication, fatal UBSan fixtures')
