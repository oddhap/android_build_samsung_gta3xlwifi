#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real checked dual-family rules + LNA + UID transport transaction, host I/O faults.

All firewall I/O must finish before LNA SET; UID SET is last. Failed writes never
publish; no post-SET rollback or complete-networking readiness is invented.
"""
import argparse,ast,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-local-network-transport24.py');subprocess.run(['python3',str(helper),'--source',str(S),'--output',str(O/'transport-regression')],check=True)
old=Path(__file__).with_name('test-permission-rule-transaction24.py');subprocess.run(['python3',str(old),'--source',str(S),'--output',str(O/'permission-transaction-regression')],check=True)
code=(O/'transport-regression/test.cpp').read_text().split('int main(){',1)[0]
code=code.replace('unsigned cases=0;','unsigned cases=0;bool firewallAllowed=true;').replace('++opens;held=true;','++opens;held=true;firewallAllowed=true;').replace('held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;','if(cmd==GTA3XLWIFI_NETPOLICY_HOLD){firewallAllowed=true;}held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;').replace('&&held);++setCalls;','&&held);++setCalls;firewallAllowed=false;').replace('assert(held);++lnaSets;','assert(held);++lnaSets;firewallAllowed=false;').replace('void resetLna(){resetImage();','void resetLna(){firewallAllowed=true;resetImage();')
other=Path(__file__).with_name('test-dualstack-uid-setup24.py');tree=ast.parse(other.read_text());extra=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.AugAssign) and isinstance(n.target,ast.Name) and n.target.id=='code');code+=extra.split('int main(){',1)[0].replace('assert(held&&opens==1);','assert(firewallAllowed&&held&&opens==1);')
header=next(ast.literal_eval(n.value.args[0]) for n in tree.body if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='write_text');(O/'IptablesRestoreController.h').write_text(header)
code+=r'''
int main(){
 resetLna();{Kernel k;D d(k);C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-ENOTCONN&&k.calls==0);C(d.start()==0&&held);C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0&&!held&&lnaRevision==1&&kernelRevision==1&&lnaSets==1&&setCalls==1);auto calls=k.calls;C(d.replace(image(120001),image(120001))==-EOPNOTSUPP&&k.calls==calls);C(d.replaceWithPermissions(image(120001),image(120001),wanted)==-EOPNOTSUPP&&k.calls==calls);C(d.replaceWithLocalNetwork(image(120001),image(120001),{}, {}, {})==0&&!held&&lnaRevision==2&&kernelRevision==2&&netImage.empty()&&hostImage.empty()&&kernelImage.empty());d.stop();C(files.empty()&&held);}
 for(auto fail:{1u,2u})for(bool commit:{false,true}){
  resetLna();Kernel k;D d(k);C(d.start()==0);k.failWriteAt=fail;k.commitFailure=commit;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EREMOTEIO&&held&&lnaSets==0&&setCalls==0&&lnaRevision==0&&kernelRevision==0&&k.uid[V4]==10001&&k.uid[V6]==10001);k.failWriteAt=0;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==0&&!held&&lnaRevision==1&&kernelRevision==1);
 }
 for(auto fail:{1u,2u})for(bool commit:{false,true}){
  resetLna();Kernel k;D d(k);C(d.start()==0&&d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0);k.writes=0;k.failWriteAt=fail;k.commitFailure=commit;C(d.replaceWithLocalNetwork(image(120001),image(120001),{}, {}, {})==-EREMOTEIO&&!held&&kernelRevision==1&&lnaRevision==1&&setCalls==1&&lnaSets==1&&k.uid[V4]==110001&&k.uid[V6]==110001);
 }
 resetLna();{Kernel k;D d(k);C(d.start()==0);auto calls=k.calls;auto bad=network;bad[0].key[23]=1;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,bad,host)==-EINVAL&&k.calls==calls&&lnaSets==0&&setCalls==0&&held);bad=network;bad.push_back(network[0]);C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,bad,host)==-EEXIST&&k.calls==calls);C(d.replaceWithLocalNetwork(image(110001),image(110001),{{1,0}},network,host)==-EINVAL&&k.calls==calls);}
 for(bool commit:{false,true}){
  resetLna();Kernel k;D d(k);C(d.start()==0);lnaSetError=EIO;lnaCommitError=commit;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&lnaRevision==(commit?1:0)&&kernelRevision==0&&setCalls==0);auto calls=k.calls;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==-ENOTCONN&&k.calls==calls);
 }
 for(bool commit:{false,true}){
  resetLna();Kernel k;D d(k);C(d.start()==0);setError=EIO;commitThenError=commit;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&lnaRevision==1&&kernelRevision==(commit?1:0));
 }
 // LNA read1,2 before-image;3 setter metadata;4,5 post-write metadata/data.
 for(unsigned call:{3u,4u,5u}){resetLna();Kernel k;D d(k);C(d.start()==0);lnaErrorAt=call;lnaError=EFAULT;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&setCalls==0);}
 for(unsigned fault:{16u,17u}){resetLna();Kernel k;D d(k);C(d.start()==0);lnaFaultAt=5;lnaFault=fault;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&setCalls==0&&lnaRevision==1);}
 resetLna();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0);hostImage[0].allowed=0;auto writes=k.writes;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetLna();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0);kernelImage[0].permissions=1;auto writes=k.writes;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetLna();{Kernel k;D d(k);C(d.start()==0&&d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==0);k.uid[V6]=99999;auto writes=k.writes;C(d.replaceWithLocalNetwork(image(120001),image(120001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&k.writes==writes);}
 resetLna();{Kernel k;D d(k);C(d.start()==0);ioctlError=EIO;errorCommand=GTA3XLWIFI_NETPOLICY_RELEASE;C(d.replaceWithLocalNetwork(image(110001),image(110001),wanted,network,host)==-EUCLEAN&&held&&files.empty()&&lnaRevision==1&&kernelRevision==1);}
 resetLna();{Kernel k;D d(k);C(d.start()==0);auto root=wanted;root.insert(root.begin(),{0,4});C(d.replaceWithLocalNetwork(image(110001),image(110001),root,network,host)==0&&!held&&kernelImage[0].uid==0&&kernelImage[0].permissions==4);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);sources=[S/n for n in ['Gta3xlwifiCheckedUidChains.cpp','Gta3xlwifiNetpolicyLease.cpp','Gta3xlwifiDualStackUidChains.cpp','Gta3xlwifiLocalNetworkState.cpp']];cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),'-I'+str(O),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=50
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,old,other,O/'test.cpp',O/'IptablesRestoreController.h',*sources,*[s.with_suffix('.h') for s in sources],*[S/'linux/netfilter'/n for n in ['gta3xlwifi_netpolicy.h','gta3xlwifi_uid_permissions.h','gta3xlwifi_local_network.h']]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':x.stderr,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'no_firewall_io_after_lna_or_uid_SET':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual combined LNA/UID/rules transaction, fatal UBSan')
