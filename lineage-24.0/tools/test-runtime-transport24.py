#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual shared-lease runtime image I/O with wire/credential lifetime fixtures.

Exercises real reset/retry, immutable revision confirmation and readback checking.
No kernel packets, service routing or whole-owner mode integration is claimed.
"""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-host','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();R=a.reference_host.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True);sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
r=json.loads((R/'report.json').read_text());assert r['passed'] and sha(R/'test.cpp')==r['inputs_sha256'][str(R/'test.cpp')]
code=(R/'test.cpp').read_text().split('int main(){',1)[0].replace('extern "C" int __wrap_ioctl(', 'extern "C" int underlyingIoctl(',1).replace('int __wrap_close(', 'int underlyingClose(',1).replace('int __wrap_open(', 'int underlyingOpen(',1)
code+=r'''
#include <linux/netfilter/gta3xlwifi_runtime_policy.h>
using RI=NetpolicyLease::RuntimeImage;
static RI runtimeImage;static unsigned gets,sets,commits,metaRetries,dataRetries,setRetries,metaFault,dataFault;
static int runtimeGetError,runtimeSetError;static bool positiveGet,positiveSet,setAfterError;
extern "C" int __wrap_open(const char*p,int flags,...){int fd=underlyingOpen(p,flags);if(fd>=0&&std::string(p)=="/dev/gta3xlwifi_netpolicy")runtimeImage.confirmedForLease=false;return fd;}
extern "C" int __wrap_close(int fd){runtimeImage.confirmedForLease=false;return underlyingClose(fd);}
extern "C" int __wrap_ioctl(int fd,unsigned long cmd,...){va_list ap;va_start(ap,cmd);unsigned long arg=va_arg(ap,unsigned long);va_end(ap);
 if(cmd==GTA3XLWIFI_NETPOLICY_RELEASE&&!runtimeImage.confirmedForLease){errno=EAGAIN;return -1;}
 if(cmd!=GTA3XLWIFI_RUNTIME_GET&&cmd!=GTA3XLWIFI_RUNTIME_SET)return underlyingIoctl(fd,cmd,arg);
 assert(files.count(fd)&&arg);auto*t=reinterpret_cast<gta3xlwifi_runtime_transfer*>(arg);assert(t->version==1&&!t->status);
 if(cmd==GTA3XLWIFI_RUNTIME_SET){++sets;assert(held&&(t->flags&~7)==0&&t->count<=1000&&bool(t->entries)==bool(t->count));std::vector<uint32_t> rows;
  if(t->count){auto*p=reinterpret_cast<const uint32_t*>(uintptr_t(t->entries));rows.assign(p,p+t->count);}
  if(runtimeSetError&&!setAfterError){errno=runtimeSetError;return positiveSet?1:-1;}
  if(t->revision==runtimeImage.revision&&t->flags==runtimeImage.flags&&rows==runtimeImage.legacyBlockedUids){}else{assert(t->revision==runtimeImage.revision+1);runtimeImage.revision=t->revision;runtimeImage.flags=t->flags;runtimeImage.legacyBlockedUids=rows;++commits;}
  runtimeImage.confirmedForLease=true;
  if(setRetries){--setRetries;errno=EINTR;return -1;}if(runtimeSetError){errno=runtimeSetError;return positiveSet?1:-1;}return 0;
 }
 ++gets;assert(!t->flags);bool data=t->entries;uint64_t ptr=t->entries;
 if(data){assert(t->revision==runtimeImage.revision&&t->count==runtimeImage.legacyBlockedUids.size());auto*rows=reinterpret_cast<uint32_t*>(uintptr_t(ptr));std::copy(runtimeImage.legacyBlockedUids.begin(),runtimeImage.legacyBlockedUids.end(),rows);if(dataFault==7)rows[0]=UINT32_MAX;if(dataFault==8)rows[1]=rows[0];if(dataFault==9)std::swap(rows[0],rows[1]);}
 else assert(!t->revision&&!t->count);
 t->count=runtimeImage.legacyBlockedUids.size();t->revision=runtimeImage.revision;t->flags=runtimeImage.flags;t->status=runtimeImage.confirmedForLease?1:0;
 unsigned fault=data?dataFault:metaFault;switch(fault){case 0:break;case 1:t->version=2;break;case 2:++t->count;break;case 3:++t->revision;break;case 4:t->flags=8;break;case 5:t->status=2;break;case 6:t->entries=77;break;case 7:case 8:case 9:assert(data);break;case 10:t->revision=0;t->status=1;break;default:assert(false);}
 if(data&&dataRetries){--dataRetries;errno=EINTR;return -1;}if(!data&&metaRetries){--metaRetries;errno=EINTR;return -1;}if(runtimeGetError){errno=runtimeGetError;return positiveGet?1:-1;}return 0;
}
static void resetRuntime(){resetEvents();features=16384;runtimeImage={};gets=sets=commits=metaRetries=dataRetries=setRetries=metaFault=dataFault=0;runtimeGetError=runtimeSetError=0;positiveGet=positiveSet=setAfterError=false;}
static RI runtimeSentinel(){RI x;x.revision=99;x.flags=66;x.confirmedForLease=true;x.legacyBlockedUids={77};return x;}
static bool runtimeUnchanged(const RI&x){return x.revision==99&&x.flags==66&&x.confirmedForLease&&x.legacyBlockedUids==std::vector<uint32_t>{77};}
int main(){
 resetRuntime();{NetpolicyLease l;RI out=runtimeSentinel();uint64_t rev=99;C(l.requireRuntimePolicy()==-ENOTCONN);C(l.readRuntimePolicy(&out)==-ENOTCONN&&runtimeUnchanged(out));C(l.start()==0);C(l.readRuntimePolicy(&out)==0&&!out.revision&&!out.confirmedForLease&&out.legacyBlockedUids.empty());metaRetries=2;C(l.readRuntimePolicy(&out)==0&&!metaRetries);C(l.replaceRuntimePolicy(0,7,{10001,110001},&rev)==0&&rev==1&&commits==1&&held&&opens==1);metaRetries=dataRetries=2;C(l.readRuntimePolicy(&out)==0&&out.flags==7&&out.confirmedForLease&&out.legacyBlockedUids==std::vector<uint32_t>({10001,110001})&&!metaRetries&&!dataRetries);setRetries=3;C(l.replaceRuntimePolicy(1,0,{},&rev)==0&&rev==2&&commits==2&&sets==5&&!setRetries);C(l.release()==0&&!held);C(l.readRuntimePolicy(&out)==0&&!held&&out.revision==2&&out.confirmedForLease);auto count=sets;C(l.replaceRuntimePolicy(2,7,{},&rev)==-EBUSY&&sets==count&&files.empty()&&held&&!runtimeImage.confirmedForLease);}
 resetRuntime();{NetpolicyLease l;RI out;C(l.start()==0&&l.release()==-EAGAIN&&files.empty()&&held);}
 resetRuntime();{NetpolicyLease l;uint64_t rev=99;C(l.start()==0);auto count=gets+sets;C(l.readRuntimePolicy(nullptr)==-EINVAL);C(l.replaceRuntimePolicy(0,8,{},&rev)==-EINVAL&&rev==99);C(l.replaceRuntimePolicy(0,7,{2,1},&rev)==-EINVAL);C(l.replaceRuntimePolicy(0,7,{1,1},&rev)==-EINVAL);C(l.replaceRuntimePolicy(0,7,{UINT32_MAX},&rev)==-EINVAL);C(l.replaceRuntimePolicy(0,7,std::vector<uint32_t>(1001),&rev)==-EINVAL);C(l.replaceRuntimePolicy(UINT64_MAX,7,{},&rev)==-EOVERFLOW);C(l.replaceRuntimePolicy(0,7,{},nullptr)==-EINVAL&&gets+sets==count&&files.size()==1&&held);}
 for(unsigned fault:{1u,4u,5u,6u,10u}){resetRuntime();metaFault=fault;NetpolicyLease l;RI out=runtimeSentinel();C(l.start()==0&&l.readRuntimePolicy(&out)==-EPROTO&&runtimeUnchanged(out)&&files.empty()&&held);}
 for(unsigned fault=1;fault<=9;fault++){resetRuntime();runtimeImage={1,7,true,{1,2}};dataFault=fault;NetpolicyLease l;RI out=runtimeSentinel();C(l.start()==0&&l.readRuntimePolicy(&out)==-EPROTO&&runtimeUnchanged(out)&&files.empty()&&held);}
 for(int error:{EIO,EFAULT,ESTALE,ENOSPC,ENOMEM,ENOTTY}){resetRuntime();runtimeGetError=error;NetpolicyLease l;RI out=runtimeSentinel();C(l.start()==0&&l.readRuntimePolicy(&out)==-error&&runtimeUnchanged(out)&&files.empty()&&held);}
 resetRuntime();runtimeGetError=EIO;positiveGet=true;{NetpolicyLease l;RI out=runtimeSentinel();C(l.start()==0&&l.readRuntimePolicy(&out)==-EPROTO&&runtimeUnchanged(out)&&files.empty());}
 for(bool after:{false,true})for(bool positive:{false,true}){resetRuntime();runtimeSetError=EIO;setAfterError=after;positiveSet=positive;NetpolicyLease l;uint64_t rev=99;C(l.start()==0&&l.replaceRuntimePolicy(0,7,{1,2},&rev)==-(positive?EPROTO:EIO)&&rev==99&&files.empty()&&held);C(runtimeImage.revision==(after?1u:0u)&&!runtimeImage.confirmedForLease);runtimeSetError=0;C(l.start()==0);RI recovered;C(l.readRuntimePolicy(&recovered)==0&&recovered.revision==(after?1u:0u)&&!recovered.confirmedForLease);C(l.replaceRuntimePolicy(recovered.revision,5,{10001},&rev)==0&&rev==(after?2u:1u));}
 for(unsigned fault:{1u,4u,5u,6u}){resetRuntime();metaFault=fault;NetpolicyLease l;uint64_t rev=99;C(l.start()==0&&l.replaceRuntimePolicy(0,7,{1,2},&rev)==-EPROTO&&rev==99&&files.empty()&&held);}
 for(int absent:{0,16383}){resetRuntime();features=absent;NetpolicyLease l;RI out=runtimeSentinel();C(l.start()==0&&l.readRuntimePolicy(&out)==-EOPNOTSUPP&&gets==0&&runtimeUnchanged(out)&&files.empty());}
 resetRuntime();{NetpolicyLease l;uint64_t rev;std::vector<uint32_t> ids;for(unsigned n=0;n<1000;n++)ids.push_back(n);C(l.start()==0&&l.replaceRuntimePolicy(0,7,ids,&rev)==0&&rev==1);RI out;C(l.readRuntimePolicy(&out)==0&&out.legacyBlockedUids==ids);}
 C(files.empty()&&held);printf("passed_cases=%u\n",cases);return 0;
}
''';(O/'test.cpp').write_text(code);cmd=['c++','-std=c++20','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-pthread','-I'+str(S),str(S/'Gta3xlwifiNetpolicyLease.cpp'),str(O/'test.cpp'),'-o',str(O/'test')]+['-Wl,--wrap='+x for x in ['open','close','read','__read_chk','fstat','fstatfs','ioctl']]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=90,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr);match=re.fullmatch(r'passed_cases=(\d+)\n',x.stdout);assert match and int(match[1])>60
paths=[Path(__file__),R/'report.json',R/'test.cpp',S/'Gta3xlwifiNetpolicyLease.cpp',S/'Gta3xlwifiNetpolicyLease.h',O/'test.cpp',*[p for p in (S/'linux/netfilter').glob('*.h')]];(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'stderr':x.stderr,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
