#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run actual UID permission image transport with syscall/protocol fault fixtures.

GNU syscall wrappers model the private device and image, including ambiguous
writes and malformed readback. No real device, kernel or network is accessed.
"""
import argparse,ast,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-netpolicy-lease24.py');tree=ast.parse(helper.read_text());code=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='code' for t in n.targets));code=code[:code.index('int main(){')]
start=code.index('extern "C" int __wrap_ioctl(');end=code.index('void reset()',start)
new=r'''
#include <linux/netfilter/gta3xlwifi_uid_permissions.h>
#include <climits>
using Wire=gta3xlwifi_uid_permission_entry;
std::vector<Wire> kernelImage;
uint64_t kernelRevision=0;
int features=7,imageIoctls=0,getCalls=0,setCalls=0,getFaultAt=0,getFault=0;
int getErrorAt=0,getError=0,setError=0,setAck=0,setEintrAfterCommit=0;
bool commitThenError=false,releaseAfterSet=false;
static bool equalWire(const std::vector<Wire>&a,const std::vector<Wire>&b){return a.size()==b.size()&&(a.empty()||!memcmp(a.data(),b.data(),a.size()*sizeof(a[0])));}
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){
 assert(files.count(fd)&&files.at(fd).path==node);
 va_list v;va_start(v,cmd);unsigned long arg=va_arg(v,unsigned long);va_end(v);
 if(ioctlEintr){--ioctlEintr;errno=EINTR;return -1;}
 if(ioctlError&&cmd==errorCommand){errno=ioctlError;return -1;}
 if(cmd>=0x6750&&cmd<=0x6753){
  assert(arg==0);
  if(cmd==GTA3XLWIFI_NETPOLICY_ABI)return abi;
  if(cmd==GTA3XLWIFI_NETPOLICY_STATE)return stateOverride>=0?stateOverride:int(held);
  held=cmd==GTA3XLWIFI_NETPOLICY_HOLD;return ack;
 }
 ++imageIoctls;
 if(cmd==GTA3XLWIFI_UID_FEATURES){assert(!arg);return features;}
 assert(arg);auto*t=reinterpret_cast<gta3xlwifi_uid_permission_transfer*>(arg);
 assert(t->version==1&&t->count<=65536&&bool(t->count)==bool(t->entries));
 auto*buffer=reinterpret_cast<Wire*>(static_cast<uintptr_t>(t->entries));
 if(cmd==GTA3XLWIFI_UID_GET_IMAGE){
  ++getCalls;if(getCalls==getErrorAt){errno=getError;return -1;}
  if(t->count){
   if(t->revision!=kernelRevision||!t->revision){errno=ESTALE;return -1;}
   assert(t->count>=kernelImage.size());if(!kernelImage.empty())memcpy(buffer,kernelImage.data(),kernelImage.size()*sizeof(Wire));
  }
  t->count=kernelImage.size();t->revision=kernelRevision;
  if(getCalls==getFaultAt){
   switch(getFault){
    case 1:t->version=2;break;
    case 2:t->count=65537;break;
    case 3:t->entries=17;break;
    case 4:++t->revision;break;
    case 5:assert(buffer&&t->count);buffer[0].permissions=128;break;
    case 6:assert(buffer&&t->count);buffer[0].uid=UINT32_MAX;break;
    case 7:assert(buffer&&t->count>1);buffer[1].uid=buffer[0].uid;break;
    case 8:assert(buffer&&t->count);buffer[0].permissions=1;break;
    case 9:assert(buffer&&t->count);buffer[0].permissions=0;break;
    case 10:t->revision=0;break;
    default:assert(false);
   }
  }
  return 0;
 }
 assert(cmd==GTA3XLWIFI_UID_SET_IMAGE&&held);++setCalls;
 if(setError&&!commitThenError){errno=setError;return -1;}
 std::vector<Wire> next;if(t->count)next.assign(buffer,buffer+t->count);
 for(size_t i=0;i<next.size();i++)assert(next[i].uid<=INT_MAX&&next[i].permissions&&next[i].permissions<128&&(!i||next[i-1].uid<next[i].uid));
 if(t->revision==kernelRevision){assert(equalWire(next,kernelImage));}
 else{assert(t->revision==kernelRevision+1);kernelImage=next;kernelRevision=t->revision;}
 if(setEintrAfterCommit){--setEintrAfterCommit;errno=EINTR;return -1;}
 if(releaseAfterSet)held=false;
 if(setError){errno=setError;return -1;}return setAck;
}
'''
code=code[:start]+new+code[end:]
code+=r'''
using EntryValue=NetpolicyLease::PermissionEntry;
using ImageValue=NetpolicyLease::PermissionImage;
void resetImage(){reset();kernelImage.clear();kernelRevision=0;features=7;imageIoctls=getCalls=setCalls=getFaultAt=getFault=getErrorAt=getError=setError=setAck=setEintrAfterCommit=0;commitThenError=releaseAfterSet=false;}
void seed(){kernelRevision=9;kernelImage={{10001,4},{110001,127}};}
ImageValue sentinel(){return {777,{{555,1}}};}
bool untouched(const ImageValue&v){return v.revision==777&&v.entries==std::vector<EntryValue>{{555,1}};}
const std::vector<EntryValue> wanted={{10001,4},{110001,127}};
int main(){
 static_assert(sizeof(gta3xlwifi_uid_permission_transfer)==24&&sizeof(Wire)==8);
 static_assert(_IOC_SIZE(GTA3XLWIFI_UID_SET_IMAGE)==24);
 resetImage();{NetpolicyLease l;ImageValue value=sentinel();uint64_t revision=888;
 C(l.readUidPermissions(nullptr)==-EINVAL);C(l.readUidPermissions(&value)==-ENOTCONN&&untouched(value));
 C(l.replaceUidPermissions(0,wanted,nullptr)==-EINVAL);C(l.replaceUidPermissions(0,wanted,&revision)==-ENOTCONN&&revision==888);
 C(l.replaceUidPermissions(UINT64_MAX,wanted,&revision)==-EOVERFLOW&&imageIoctls==0);
 C(l.start()==0);C(l.readUidPermissions(&value)==0&&value.revision==0&&value.entries.empty()&&held);
 int before=imageIoctls;
 for(auto invalid:std::vector<std::vector<EntryValue>>{{{-1,1}},{{1,0}},{{1,128}},{{2,1},{1,1}},{{1,1},{1,2}},std::vector<EntryValue>(65537,{1,1})}){
  C(l.replaceUidPermissions(0,invalid,&revision)==-EINVAL&&imageIoctls==before&&held&&opens==1&&revision==888);
 }
 C(l.replaceUidPermissions(0,wanted,&revision)==0&&revision==1&&held&&opens==1&&setCalls==1);
 C(l.readUidPermissions(&value)==0&&value.revision==1&&value.entries==wanted&&held);
 C(l.replaceUidPermissions(1,{},&revision)==0&&revision==2&&kernelImage.empty()&&held);
 C(l.readUidPermissions(&value)==0&&value.revision==2&&value.entries.empty());
 C(l.replaceUidPermissions(2,wanted,&revision)==0&&revision==3&&held); // semantic rollback advances generation
 std::vector<std::thread> threads;for(int i=0;i<16;i++)threads.emplace_back([&l]{ImageValue v;assert(l.readUidPermissions(&v)==0&&v.revision==3&&v.entries==wanted);});for(auto&t:threads)t.join();C(held&&opens==1);
 }
 C(files.empty()&&held);
 for(int missing:{0,1,3,5,6}){resetImage();features=missing;NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);C(l.readUidPermissions(&v)==-EOPNOTSUPP&&untouched(v)&&files.empty()&&held);}
 resetImage();{NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);ioctlError=ENOTTY;errorCommand=GTA3XLWIFI_UID_FEATURES;C(l.readUidPermissions(&v)==-ENOTTY&&untouched(v)&&held&&files.empty());}
 // Each malformed metadata response is rejected before trusting a size/pointer.
 for(int fault:{1,2,3,10}){resetImage();seed();getFaultAt=1;getFault=fault;NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);C(l.readUidPermissions(&v)==-EPROTO&&untouched(v)&&files.empty()&&held);}
 for(int fault:{1,2,3,4,5,6,7,9,10}){resetImage();seed();getFaultAt=2;getFault=fault;NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);C(l.readUidPermissions(&v)==-EPROTO&&untouched(v)&&files.empty()&&held);}
 for(int call:{1,2}){resetImage();seed();getErrorAt=call;getError=EFAULT;NetpolicyLease l;ImageValue v=sentinel();C(l.start()==0);C(l.readUidPermissions(&v)==-EFAULT&&untouched(v)&&files.empty()&&held);}
 resetImage();{NetpolicyLease l;uint64_t revision=888;C(l.start()==0&&l.release()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EBUSY&&revision==888&&setCalls==0&&held&&files.empty());}
 resetImage();seed();{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(8,wanted,&revision)==-ESTALE&&revision==888&&setCalls==0&&held&&files.empty());}
 for(bool commit:{false,true}){resetImage();setError=EIO;commitThenError=commit;NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EIO&&revision==888&&kernelRevision==(commit?1:0)&&files.empty()&&held);}
 resetImage();setEintrAfterCommit=1;{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==0&&revision==1&&kernelRevision==1&&setCalls==2&&held);}
 resetImage();setAck=1;{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EPROTO&&revision==888&&kernelRevision==1&&held&&files.empty());}
 for(int call:{2,3}){resetImage();getErrorAt=call;getError=ESTALE;NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-ESTALE&&revision==888&&kernelRevision==1&&held&&files.empty());}
 for(int call:{2,3}){resetImage();getFaultAt=call;getFault=4;NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EPROTO&&revision==888&&kernelRevision==1&&held&&files.empty());}
 resetImage();getFaultAt=3;getFault=8;{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EPROTO&&revision==888&&kernelRevision==1&&held&&files.empty());}
 resetImage();releaseAfterSet=true;{NetpolicyLease l;uint64_t revision=888;C(l.start()==0);C(l.replaceUidPermissions(0,wanted,&revision)==-EPROTO&&revision==888&&held&&files.empty());}
 resetImage();{NetpolicyLease l;C(l.start()==0);std::vector<EntryValue> many;for(int32_t i=0;i<65536;i++)many.push_back({2*i,1});uint64_t revision=0;ImageValue v;C(l.replaceUidPermissions(0,many,&revision)==0&&revision==1);C(l.readUidPermissions(&v)==0&&v.entries==many&&v.revision==1&&held);}
 C(files.empty()&&held);
 printf("passed_cases=%u\n",cases);
}
'''
(O/'test.cpp').write_text(code)
cmd=['c++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(S/'Gta3xlwifiNetpolicyLease.cpp'),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=60);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
m=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert m and int(m[1])>=80
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,O/'test.cpp',S/'Gta3xlwifiNetpolicyLease.cpp',S/'Gta3xlwifiNetpolicyLease.h',S/'linux/netfilter/gta3xlwifi_netpolicy.h',S/'linux/netfilter/gta3xlwifi_uid_permissions.h']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(m[1]),'stderr':x.stderr,'command':cmd,'inputs_sha256':{str(p.resolve()):sha(p) for p in paths},'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual transport with UID image/protocol/syscall fixtures, fatal UBSan')
