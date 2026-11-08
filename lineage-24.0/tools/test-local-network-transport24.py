#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual leased two-table LNA I/O with malformed-response/ambiguous-write fixtures.

Host syscall device model only; includes original UID transport regression.
No real kernel packets, complete backend publication or hardware readiness.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-uid-permission-transport24.py');subprocess.run(['python3',str(helper),'--source',str(S),'--output',str(O/'uid-regression')],check=True)
code=(O/'uid-regression/test.cpp').read_text().split('int main(){',1)[0].replace('extern "C" int __wrap_ioctl(', 'extern "C" int uid_ioctl(')
code+=r'''
#include <linux/netfilter/gta3xlwifi_local_network.h>
using LWire=gta3xlwifi_lna_entry;using LEntry=NetpolicyLease::LocalNetworkEntry;using LImage=NetpolicyLease::LocalNetworkImage;
std::vector<LWire> netImage,hostImage;uint64_t lnaRevision=0;
unsigned lnaIoctls=0,lnaGets=0,lnaSets=0;unsigned lnaFaultAt=0,lnaFault=0,lnaErrorAt=0;int lnaError=0,lnaSetError=0,lnaAck=0,lnaEintr=0;
bool lnaCommitError=false,lnaReleaseAfterSet=false;
bool equalLWire(const std::vector<LWire>&a,const std::vector<LWire>&b){return a.size()==b.size()&&(a.empty()||!memcmp(a.data(),b.data(),a.size()*sizeof(LWire)));}
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
 va_list args;va_start(args,cmd);unsigned long arg=va_arg(args,unsigned long);va_end(args);
 if(cmd!=GTA3XLWIFI_LNA_SET_IMAGE&&cmd!=GTA3XLWIFI_LNA_GET_IMAGE)return uid_ioctl(fd,cmd,arg);
 assert(files.count(fd)&&files.at(fd).path==node);++lnaIoctls;
 if(ioctlEintr){--ioctlEintr;errno=EINTR;return -1;}
 if(ioctlError&&cmd==errorCommand){errno=ioctlError;return -1;}
 assert(arg);auto*t=reinterpret_cast<gta3xlwifi_lna_transfer*>(arg);assert(t->version==1&&!t->reserved&&t->network_count<=1000&&t->host_count<=1000&&bool(t->network_count)==bool(t->network_entries)&&bool(t->host_count)==bool(t->host_entries));
 auto*n=reinterpret_cast<LWire*>(static_cast<uintptr_t>(t->network_entries));auto*h=reinterpret_cast<LWire*>(static_cast<uintptr_t>(t->host_entries));
 if(cmd==GTA3XLWIFI_LNA_GET_IMAGE){
  ++lnaGets;if(lnaGets==lnaErrorAt){errno=lnaError;return -1;}
  if(t->network_count||t->host_count){
   if(t->revision!=lnaRevision||!t->revision){errno=ESTALE;return -1;}
   assert(t->network_count>=netImage.size()&&t->host_count>=hostImage.size());if(!netImage.empty())memcpy(n,netImage.data(),netImage.size()*sizeof(LWire));if(!hostImage.empty())memcpy(h,hostImage.data(),hostImage.size()*sizeof(LWire));
  }
  t->revision=lnaRevision;t->network_count=netImage.size();t->host_count=hostImage.size();
  if(lnaGets==lnaFaultAt){switch(lnaFault){
   case 1:t->version=2;break;case 2:t->reserved=1;break;case 3:t->network_count=1001;break;case 4:t->host_count=1001;break;
   case 5:t->network_entries=17;break;case 6:t->host_entries=18;break;case 7:++t->revision;break;case 8:t->revision=0;break;
   case 9:n[0].prefix_bits=193;break;case 10:h[0].allowed=2;break;case 11:n[0].reserved[2]=1;break;case 12:h[0].reserved[0]=1;break;
   case 13:n[0].key[23]=1;break;case 14:n[1]=n[0];break;case 15:std::swap(h[0],h[1]);break;case 16:n[0].allowed=!n[0].allowed;break;case 17:h[0].allowed=!h[0].allowed;break;
   case 18:--t->network_count;break;case 19:--t->host_count;break;default:assert(false);
  }}return 0;
 }
 assert(held);++lnaSets;if(lnaSetError&&!lnaCommitError){errno=lnaSetError;return -1;}
 std::vector<LWire> nextN,nextH;if(t->network_count)nextN.assign(n,n+t->network_count);if(t->host_count)nextH.assign(h,h+t->host_count);
 if(t->revision==lnaRevision){assert(equalLWire(nextN,netImage)&&equalLWire(nextH,hostImage));}
 else{assert(t->revision==lnaRevision+1);netImage=nextN;hostImage=nextH;lnaRevision=t->revision;}
 if(lnaEintr){--lnaEintr;errno=EINTR;return -1;}if(lnaReleaseAfterSet)held=false;if(lnaSetError){errno=lnaSetError;return -1;}return lnaAck;
}
LEntry entry(uint32_t bits,uint8_t first,bool allow){LEntry e={bits,{},allow};e.key[0]=first;return e;}
const std::vector<LEntry> network={entry(0,0,false),entry(64,1,true),entry(192,2,false)},host={entry(64,3,true),entry(192,4,true)};
std::vector<LWire> encode(const std::vector<LEntry>&v){std::vector<LWire>w(v.size());for(size_t i=0;i<v.size();i++){w[i].prefix_bits=v[i].prefixBits;memcpy(w[i].key,v[i].key.data(),24);w[i].allowed=v[i].allowed;}return w;}
void resetLna(){resetImage();features=127;netImage.clear();hostImage.clear();lnaRevision=0;lnaIoctls=lnaGets=lnaSets=lnaFaultAt=lnaFault=lnaErrorAt=0;lnaError=lnaSetError=lnaAck=lnaEintr=0;lnaCommitError=lnaReleaseAfterSet=false;}
void seedLna(){lnaRevision=9;netImage=encode(network);hostImage=encode(host);}
LImage sentinelLna(){return {777,{entry(192,77,true)},{entry(64,88,false)}};}
bool untouchedLna(const LImage&v){auto expected=sentinelLna();return v.revision==expected.revision&&v.network==expected.network&&v.host==expected.host;}
int main(){
 static_assert(sizeof(gta3xlwifi_lna_transfer)==40&&sizeof(LWire)==32);static_assert(GTA3XLWIFI_LNA_SET_IMAGE==0x40286757&&GTA3XLWIFI_LNA_GET_IMAGE==0xc0286758);
 resetLna();{NetpolicyLease l;LImage value=sentinelLna();uint64_t revision=888;
 C(l.readLocalNetwork(nullptr)==-EINVAL);C(l.readLocalNetwork(&value)==-ENOTCONN&&untouchedLna(value));C(l.replaceLocalNetwork(0,network,host,nullptr)==-EINVAL);C(l.replaceLocalNetwork(UINT64_MAX,network,host,&revision)==-EOVERFLOW&&lnaIoctls==0);C(l.replaceLocalNetwork(0,network,host,&revision)==-ENOTCONN&&revision==888);
 C(l.start()==0);C(l.readLocalNetwork(&value)==0&&value.revision==0&&value.network.empty()&&value.host.empty()&&held);
 C(l.replaceLocalNetwork(0,network,host,&revision)==0&&revision==1&&held&&opens==1);C(l.readLocalNetwork(&value)==0&&value.revision==1&&value.network==network&&value.host==host);
 C(l.replaceLocalNetwork(1,{},host,&revision)==0&&revision==2&&netImage.empty());C(l.readLocalNetwork(&value)==0&&value.network.empty()&&value.host==host);
 C(l.replaceLocalNetwork(2,network,{},&revision)==0&&revision==3&&hostImage.empty());C(l.readLocalNetwork(&value)==0&&value.network==network&&value.host.empty());
 C(l.replaceLocalNetwork(3,{}, {},&revision)==0&&revision==4);C(l.readLocalNetwork(&value)==0&&value.revision==4&&value.network.empty()&&value.host.empty());
 }
 for(unsigned missing:{0u,7u,32u,64u,119u}){resetLna();features=missing;NetpolicyLease l;LImage v=sentinelLna();C(l.start()==0);C(l.readLocalNetwork(&v)==-EOPNOTSUPP&&untouchedLna(v)&&files.empty()&&held&&lnaIoctls==0);}
 // Store-only feature is enough for this primitive, never a readiness assertion.
 resetLna();features=8;{NetpolicyLease l;LImage v;C(l.start()==0&&l.readLocalNetwork(&v)==0&&held);}
 for(unsigned fault:{1u,2u,3u,4u,5u,6u,8u}){resetLna();seedLna();lnaFaultAt=1;lnaFault=fault;NetpolicyLease l;LImage v=sentinelLna();C(l.start()==0);C(l.readLocalNetwork(&v)==-EPROTO&&untouchedLna(v)&&files.empty()&&held);}
 for(unsigned fault:{1u,2u,3u,4u,5u,6u,7u,8u,9u,10u,11u,12u,13u,14u,15u,18u,19u}){resetLna();seedLna();lnaFaultAt=2;lnaFault=fault;NetpolicyLease l;LImage v=sentinelLna();C(l.start()==0);C(l.readLocalNetwork(&v)==-EPROTO&&untouchedLna(v)&&files.empty()&&held);}
 for(unsigned call:{1u,2u}){resetLna();seedLna();lnaErrorAt=call;lnaError=EFAULT;NetpolicyLease l;LImage v=sentinelLna();C(l.start()==0);C(l.readLocalNetwork(&v)==-EFAULT&&untouchedLna(v)&&files.empty()&&held);}
 resetLna();{NetpolicyLease l;uint64_t rev=888;C(l.start()==0&&l.release()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EBUSY&&rev==888&&files.empty()&&held&&lnaSets==0);}
 resetLna();seedLna();{NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(8,network,host,&rev)==-ESTALE&&rev==888&&files.empty()&&held&&lnaSets==0);}
 for(bool commit:{false,true}){resetLna();lnaSetError=EIO;lnaCommitError=commit;NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EIO&&rev==888&&files.empty()&&held&&lnaRevision==(commit?1:0));}
 resetLna();lnaEintr=1;{NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==0&&rev==1&&lnaRevision==1&&lnaSets==2&&held);}
 resetLna();lnaAck=1;{NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EPROTO&&rev==888&&lnaRevision==1&&held&&files.empty());}
 for(unsigned call:{2u,3u}){resetLna();lnaErrorAt=call;lnaError=ESTALE;NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-ESTALE&&rev==888&&held&&files.empty()&&lnaRevision==1);}
 for(unsigned fault:{7u,16u,17u}){resetLna();lnaFaultAt=3;lnaFault=fault;NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EPROTO&&rev==888&&held&&files.empty()&&lnaRevision==1);}
 resetLna();lnaReleaseAfterSet=true;{NetpolicyLease l;uint64_t rev=888;C(l.start()==0);C(l.replaceLocalNetwork(0,network,host,&rev)==-EPROTO&&rev==888&&held&&files.empty());}
 // Every prefix boundary, and the first ignored bit, exercise canonical wire keys.
 resetLna();{NetpolicyLease l;uint64_t rev=0;C(l.start()==0);
 for(unsigned bits=0;bits<=192;bits++){LEntry e={bits,{},bool(bits&1)};if(bits)e.key[(bits-1)/8]=1u<<(7-(bits-1)%8);C(l.replaceLocalNetwork(rev,{e},{},&rev)==0&&rev==bits+1&&held);LImage v;C(l.readLocalNetwork(&v)==0&&v.network==std::vector<LEntry>{e}&&v.host.empty());if(bits<192){e.key[bits/8]|=1u<<(7-bits%8);unsigned before=lnaIoctls;C(l.replaceLocalNetwork(rev,{e},{},&rev)==-EINVAL&&lnaIoctls==before&&opens==1&&held);}}
 for(auto invalid:std::vector<std::vector<LEntry>>{{entry(193,0,true)},{entry(0,1,true)},{entry(64,2,true),entry(64,1,false)},{entry(64,1,true),entry(64,1,false)},std::vector<LEntry>(1001,entry(0,0,true))}){unsigned before=lnaIoctls;C(l.replaceLocalNetwork(rev,invalid,{},&rev)==-EINVAL&&lnaIoctls==before);C(l.replaceLocalNetwork(rev,{},invalid,&rev)==-EINVAL&&lnaIoctls==before);}
 }
 resetLna();{NetpolicyLease l;uint64_t rev=0;C(l.start()==0);std::vector<LEntry> many;for(unsigned i=0;i<1000;i++){auto e=entry(192,0,i&1);e.key[22]=i>>8;e.key[23]=i&255;many.push_back(e);}C(l.replaceLocalNetwork(0,many,many,&rev)==0&&rev==1);LImage v;C(l.readLocalNetwork(&v)==0&&v.network==many&&v.host==many);std::vector<std::thread> threads;for(int i=0;i<16;i++)threads.emplace_back([&l,&many]{LImage v;assert(l.readLocalNetwork(&v)==0&&v.network==many&&v.host==many&&v.revision==1);});for(auto&t:threads)t.join();C(held&&opens==1);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code);sources=[S/'Gta3xlwifiNetpolicyLease.cpp'];cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),*map(str,sources),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=650
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,O/'test.cpp',*sources,S/'Gta3xlwifiNetpolicyLease.h',*[S/'linux/netfilter'/n for n in ['gta3xlwifi_netpolicy.h','gta3xlwifi_uid_permissions.h','gta3xlwifi_local_network.h']]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':x.stderr,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'all_193_prefixes_checked':True,'both_tables_capacity1000_checked':True,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual LNA transport, fatal UBSan syscall fixtures')
