#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual checked rules, lease and combined UID image transaction with I/O fixtures.

Orders a real two-family parser/transaction and checked permission transport over
synthetic rule/syscall tables. Prohibits firewall I/O after permission SET until
the next HOLD, tests rollback/quarantine; no kernel packets or global readiness.
"""
import argparse,ast,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-uid-permission-transport24.py');subprocess.run(['python3',str(helper),'--source',str(S),'--output',str(O/'transport-regression')],check=True)
code=(O/'transport-regression/test.cpp').read_text().split('int main(){',1)[0]
code=code.replace('unsigned cases=0;','unsigned cases=0;bool firewallAllowed=true;').replace('++opens;held=true;','++opens;held=true;firewallAllowed=true;').replace('held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;','if(cmd==GTA3XLWIFI_NETPOLICY_HOLD){firewallAllowed=true;}held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;').replace('&&held);++setCalls;','&&held);++setCalls;firewallAllowed=false;').replace('void resetImage(){reset();','void resetImage(){firewallAllowed=true;reset();')
other=Path(__file__).with_name('test-dualstack-uid-setup24.py');tree=ast.parse(other.read_text());extra=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.AugAssign) and isinstance(n.target,ast.Name) and n.target.id=='code');code+=extra.split('int main(){',1)[0].replace('assert(held&&opens==1);','assert(firewallAllowed&&held&&opens==1);')
header=next(ast.literal_eval(n.value.args[0]) for n in tree.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='write_text');(O/'IptablesRestoreController.h').write_text(header)
code+=r'''
int main(){
 resetImage();{Kernel k;D d(k);C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-ENOTCONN&&k.calls==0);C(d.start()==0&&held);C(d.replaceWithPermissions(image(110001),image(110001),wanted)==0&&!held&&kernelRevision==1&&setCalls==1&&k.uid[V4]==110001&&k.uid[V6]==110001);auto calls=k.calls;C(d.replace(image(120001),image(120001))==-EOPNOTSUPP&&k.calls==calls&&!held);C(d.replaceWithPermissions(image(120001),image(120001),{})==0&&!held&&kernelRevision==2&&kernelImage.empty());d.stop();C(files.empty()&&held);}
 for(auto fail:{1u,2u})for(bool commit:{false,true}){
  resetImage();Kernel k;D d(k);C(d.start()==0);k.failWriteAt=fail;k.commitFailure=commit;
  C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EREMOTEIO&&held&&kernelRevision==0&&setCalls==0&&k.uid[V4]==10001&&k.uid[V6]==10001);
  k.failWriteAt=0;C(d.replaceWithPermissions(image(120001),image(120001),wanted)==0&&!held&&kernelRevision==1);
 }
 for(auto fail:{1u,2u})for(bool commit:{false,true}){
  resetImage();Kernel k;D d(k);C(d.start()==0&&d.replaceWithPermissions(image(110001),image(110001),wanted)==0);k.writes=0;k.failWriteAt=fail;k.commitFailure=commit;
  C(d.replaceWithPermissions(image(120001),image(120001),{})==-EREMOTEIO&&!held&&kernelRevision==1&&setCalls==1&&k.uid[V4]==110001&&k.uid[V6]==110001);
 }
 resetImage();{Kernel k;D d(k);C(d.start()==0);auto bad=image(110001);bad[0].name="foreign";auto calls=k.calls;C(d.replaceWithPermissions(bad,image(110001),wanted)==-EINVAL&&k.calls==calls&&setCalls==0);C(d.replaceWithPermissions(image(110001),image(110001),{{1,0}})==-EINVAL&&k.calls==calls);C(d.replaceWithPermissions(image(110001),image(110001),{{2,1},{1,1}})==-EINVAL&&k.calls==calls);}
 for(bool commit:{false,true}){
  resetImage();Kernel k;D d(k);C(d.start()==0);setError=EIO;commitThenError=commit;
  C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty()&&kernelRevision==(commit?1:0));auto calls=k.calls;C(d.replaceWithPermissions(image(120001),image(120001),{})==-ENOTCONN&&k.calls==calls);
 }
 for(int failure:{1,2,3}){
  resetImage();Kernel k;D d(k);C(d.start()==0);getErrorAt=failure+2;getError=EFAULT;
  // Before-image GETs1,2; setter pre-metadata3; post-write metadata4; data5.
  C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty());
 }
 resetImage();{Kernel k;D d(k);C(d.start()==0);k.changeHooksOnWrite=true;C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty()&&setCalls==0);}
 resetImage();{Kernel k;D d(k);C(d.start()==0);k.failAfter=2;C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty()&&setCalls==0);}
 resetImage();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithPermissions(image(110001),image(110001),wanted)==0);kernelImage[0].permissions=1;auto writes=k.writes;C(d.replaceWithPermissions(image(120001),image(120001),wanted)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetImage();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithPermissions(image(110001),image(110001),wanted)==0);k.uid[V6]=99999;auto writes=k.writes;C(d.replaceWithPermissions(image(120001),image(120001),wanted)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetImage();{Kernel k;D d(k);C(d.start()==0);ioctlError=EIO;errorCommand=GTA3XLWIFI_NETPOLICY_RELEASE;C(d.replaceWithPermissions(image(110001),image(110001),wanted)==-EUCLEAN&&held&&files.empty()&&kernelRevision==1);}
 resetImage();{Kernel k;D d(k);C(d.start()==0);auto root=wanted;root.insert(root.begin(),{0,4});C(d.replaceWithPermissions(image(110001),image(110001),root)==0&&!held&&kernelImage[0].uid==0&&kernelImage[0].permissions==4);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);sources=[S/n for n in ['Gta3xlwifiCheckedUidChains.cpp','Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiDualStackUidChains.cpp']]
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=50
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,other,O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[s.with_suffix('.h') for s in sources],S/'linux/netfilter/gta3xlwifi_netpolicy.h',S/'linux/netfilter/gta3xlwifi_uid_permissions.h']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':x.stderr,'command':cmd,'inputs_sha256':{str(p.resolve()):sha(p) for p in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual combined UID transaction, fatal UBSan fixtures')
