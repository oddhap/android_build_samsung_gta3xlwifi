#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise actual legacy init/keyutils/vold bodies with synthetic syscall fixtures.

Uses the real Android17 descriptor SHA512 and KeyBuffer allocator. Kernel key
permissions, filesystem cipher I/O, open-inode lifetime and TEE are not exercised.
No real keyring syscall or device/user key material is accessed.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['staging','top','kernel','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir();r=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('extract',r/'test-netlink-xperm24.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def function(text,name):
 # The shared C extractor does not accept C++ qualified return types. Mask
 # only that signature with equal-width spaces, then return original bytes.
 signature='std::string '+name+'('
 masked=text.replace(signature,'     string '+name+'(')
 fragment=m.function(masked,name);start=masked.index(fragment)
 return text[start:start+len(fragment)]
vold=a.staging/'system/vold/KeyUtil.cpp';init=a.staging/'system/core/init/init.cpp';keyutils=a.staging/'system/core/libgta3xlwifi_keyutils'
v=vold.read_text();i=init.read_text();bpf=a.top/'bionic/libc/kernel/uapi/linux/fscrypt.h';fsheader=a.top/'system/extras/libfscrypt/include/fscrypt/fscrypt.h';buf=a.top/'system/vold/KeyBuffer.h'
lib=a.top/'out/soong/.intermediates/external/boringssl/libcrypto_static/linux_glibc_x86_64_static/libcrypto_static.a'
boringssl=a.top/'external/boringssl/src/include'
linker=a.top/'prebuilts/clang/host/linux-x86/clang-r584948/bin/ld.lld'
compiler=Path(shutil.which('clang++')).resolve()
prefix=v[v.index('#ifdef GTA3XLWIFI_LEGACY_FSCRYPT\n// Samsung'):v.index('// Build a struct fscrypt_key_specifier')]
functions='\n'.join(function(v,n) for n in ['generateKeyRef','keyrefstring'])+'\n'+prefix+'\n'+ '\n'.join(function(v,n) for n in ['buildKeySpecifier','installKey','evictKey'])
setup=function(i,'SetupLegacyFscryptKeyrings')
kernel_header=a.kernel/'include/uapi/linux/fs.h';ktext=kernel_header.read_text()
assert re.search(r'^#define FS_MAX_KEY_SIZE\s+64\s*$',ktext,re.M)
assert re.search(r'^#define FS_KEY_DESCRIPTOR_SIZE\s+8\s*$',ktext,re.M)
kstruct=re.search(r'struct fscrypt_key \{.*?\n};',ktext,re.S)[0].replace('struct fscrypt_key','struct samsung_fscrypt_key').replace('FS_MAX_KEY_SIZE','FSCRYPT_MAX_KEY_SIZE')
abi=kstruct+'''\nstatic_assert(sizeof(samsung_fscrypt_key)==sizeof(fscrypt_key));
static_assert(sizeof(fscrypt_key)==72);
static_assert(offsetof(samsung_fscrypt_key,mode)==offsetof(fscrypt_key,mode));
static_assert(offsetof(samsung_fscrypt_key,raw)==offsetof(fscrypt_key,raw));
static_assert(offsetof(samsung_fscrypt_key,size)==offsetof(fscrypt_key,size));
'''

header=r'''
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include <sys/syscall.h>
#include <openssl/sha.h>
#include "FSCRYPT_UAPI"
#include "FSCRYPT_OPTIONS"
static size_t zeroed;
static void* host_memset_explicit(void *p,int c,size_t n){volatile unsigned char *b=(volatile unsigned char*)p;for(size_t k=0;k<n;k++)b[k]=c;zeroed+=n;return p;}
#define memset_explicit host_memset_explicit
#include "KEY_BUFFER"
#undef memset_explicit
#include <keyutils.h>
struct Logger{template<class T>Logger& operator<<(const T&){return *this;}};
#define LOG(x) Logger()
#define PLOG(x) Logger()
using android::vold::KeyBuffer;
using android::fscrypt::KeyType;
using android::fscrypt::EncryptionOptions;
using android::fscrypt::EncryptionPolicy;
static std::mutex fscrypt_keyring_mutex;
static int io_error=ENOTTY,open_error,session_error,search_error,ring_error,add_fail,unlink_fail;
static unsigned adds,unlinks,searches,syncs,drops,session_calls,ring_adds,io_calls;
static bool ring_exists,drop_ok=true;
static std::map<std::string,int> names;
static std::map<int,std::vector<char>> payloads;
static int nextid=100;
static std::vector<char> expected_key;
extern "C" long host_syscall(long number,...){
 va_list ap;va_start(ap,number);long result=-1;
 if(number==__NR_add_key){
  auto type=va_arg(ap,const char*);auto name=va_arg(ap,const char*);auto data=va_arg(ap,const void*);auto size=va_arg(ap,size_t);int ring=va_arg(ap,int);
  if(!strcmp(type,"keyring")){assert(!strcmp(name,"fscrypt")&&!data&&!size&&ring==KEY_SPEC_SESSION_KEYRING);ring_adds++;if(ring_error)errno=ring_error;else{ring_exists=true;result=50;}}
  else{assert(!strcmp(type,"logon")&&ring==50&&size==sizeof(fscrypt_key));adds++;if(add_fail==(int)adds)errno=ENOMEM;else{
   const auto *k=(const fscrypt_key*)data;assert(k->mode==0&&k->size==64&&memcmp(k->raw,expected_key.data(),64)==0);
   result=nextid++;names[name]=result;payloads[result]=std::vector<char>((char*)data,(char*)data+size);
  }}
 }else if(number==__NR_keyctl){
  int command=va_arg(ap,int);
  if(command==KEYCTL_GET_KEYRING_ID){assert(va_arg(ap,int)==KEY_SPEC_SESSION_KEYRING&&va_arg(ap,int)==1);session_calls++;if(session_error)errno=session_error;else result=40;}
  else if(command==KEYCTL_SEARCH){int ring=va_arg(ap,int);auto type=va_arg(ap,const char*);auto name=va_arg(ap,const char*);assert(va_arg(ap,int)==0);searches++;
   if(search_error)errno=search_error;
   else if(ring==KEY_SPEC_SESSION_KEYRING){assert(!strcmp(type,"keyring")&&!strcmp(name,"fscrypt"));if(ring_exists)result=50;else errno=ENOKEY;}
   else{assert(ring==50&&!strcmp(type,"logon"));auto x=names.find(name);if(x==names.end())errno=ENOKEY;else result=x->second;}
  }else if(command==KEYCTL_UNLINK){int id=va_arg(ap,int);assert(va_arg(ap,int)==50);unlinks++;if(unlink_fail==(int)unlinks)errno=EACCES;else{for(auto x=names.begin();x!=names.end();){if(x->second==id)x=names.erase(x);else ++x;}payloads.erase(id);result=0;}}
  else assert(false);
 }else assert(false);
 va_end(ap);return result;
}
#define syscall host_syscall
#include "KEYUTILS_SOURCE"
#undef syscall
static int host_open(const char*,int){if(open_error){errno=open_error;return -1;}return 3;}
static int host_ioctl(int fd,unsigned long request,void *arg){assert(fd==3);io_calls++;if(io_error){errno=io_error;return -1;}
 if(request==FS_IOC_ADD_ENCRYPTION_KEY){auto *a=(fscrypt_add_key_arg*)arg;if(a->key_spec.type==FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER)memset(a->key_spec.u.identifier,0xa5,FSCRYPT_KEY_IDENTIFIER_SIZE);}
 return 0;
}
static void host_sync(){syncs++;}
namespace android::base{class unique_fd{int fd;public:explicit unique_fd(int x):fd(x){}operator int()const{return fd;}bool operator==(int x)const{return fd==x;}};}
static bool writeStringToFile(const std::string& value,const std::string& path){assert(value=="2"&&path=="/proc/sys/vm/drop_caches");drops++;return drop_ok;}
static void waitForBusyFiles(fscrypt_key_specifier,std::string,std::string){}
#define open host_open
#define ioctl host_ioctl
#define sync host_sync
'''
header=header.replace('FSCRYPT_UAPI',str(bpf)).replace('FSCRYPT_OPTIONS',str(fsheader)).replace('KEY_BUFFER',str(buf)).replace('KEYUTILS_SOURCE',str(keyutils/'keyutils.cpp'))
main=r'''
static void reset(){io_error=ENOTTY;open_error=session_error=search_error=ring_error=add_fail=unlink_fail=0;adds=unlinks=searches=syncs=drops=session_calls=ring_adds=io_calls=0;ring_exists=true;drop_ok=true;names.clear();payloads.clear();}
int main(){
 KeyBuffer key(64);for(unsigned k=0;k<64;k++)key[k]=k;expected_key.assign(key.begin(),key.end());
 EncryptionOptions options;options.version=1;options.key_type=KeyType::kRaw;options.flags=0;options.dusize_4k=false;
 EncryptionPolicy policy;unsigned cases=0;
 // The unchanged real A17 descriptor SHA512 must match an independent Python digest.
 assert(keyrefstring(generateKeyRef((const uint8_t*)key.data(),key.size()))=="EXPECTED_DESCRIPTOR");cases++;
 for(int error:{EACCES,EINVAL,ENODEV,ENOENT,ENOSPC,EPERM,EIO}){
  reset();io_error=error;assert(!installKey("/data",options,key,&policy)&&adds==0&&searches==0);cases++;
  policy.options=options;policy.key_raw_ref=std::string(8,'x');assert(!evictKey("/data",policy)&&searches==0&&drops==0);cases++;
 }
 reset();io_error=0;assert(installKey("/data",options,key,&policy)&&policy.key_raw_ref.size()==8&&adds==0);assert(evictKey("/data",policy)&&drops==0);cases+=2;
 reset();io_error=0;options.version=2;assert(installKey("/data",options,key,&policy)&&policy.key_raw_ref==std::string(16,'\xa5')&&adds==0);cases++;
 options.version=1;
 reset();open_error=EACCES;assert(!installKey("/data",options,key,&policy)&&searches==0&&io_calls==0);cases++;
 for(int version:{1,2})for(auto type:{KeyType::kRaw,KeyType::kHwWrappedV0,KeyType::kHwWrapped}){
  reset();options.version=version;options.key_type=type;
  const bool expected=
#ifdef GTA3XLWIFI_LEGACY_FSCRYPT
   version==1&&type==KeyType::kRaw;
#else
   false;
#endif
  assert(installKey("/data",options,key,&policy)==expected);assert(adds==(expected?3u:0u));cases++;
  if(!expected){assert(searches==0);policy.options=options;policy.key_raw_ref=std::string(version==1?8:16,'x');assert(!evictKey("/data",policy)&&drops==0&&searches==0);cases++;}
 }
 options.version=1;options.key_type=KeyType::kRaw;
#ifdef GTA3XLWIFI_LEGACY_FSCRYPT
 reset();ring_exists=false;assert(SetupLegacyFscryptKeyrings()&&session_calls==1&&ring_adds==1);assert(SetupLegacyFscryptKeyrings()&&ring_adds==1);cases+=2;
 for(int which=0;which<3;which++){reset();ring_exists=false;if(which==0)session_error=EPERM;else if(which==1)search_error=EACCES;else ring_error=ENOMEM;assert(!SetupLegacyFscryptKeyrings());cases++;}
 reset();assert(installKey("/data",options,key,&policy)&&names.size()==3&&adds==3);unsigned oldadds=adds;assert(installKey("/data",options,key,&policy)&&adds==oldadds);assert(evictKey("/data",policy)&&names.empty()&&unlinks==3&&syncs==1&&drops==1);assert(evictKey("/data",policy)&&names.empty()&&drops==2);cases+=4;
 for(int fail=1;fail<=3;fail++){reset();add_fail=fail;assert(!installKey("/data",options,key,&policy)&&names.empty()&&unlinks==(unsigned)fail-1);cases++;}
 for(int fail=1;fail<=2;fail++){reset();std::string ref=keyrefstring(generateKeyRef((const uint8_t*)key.data(),key.size()));names["ext4:"+ref]=99;add_fail=fail;assert(!installKey("/data",options,key,&policy)&&names.size()==1&&names.begin()->second==99);cases++;}
 reset();add_fail=2;unlink_fail=1;assert(!installKey("/data",options,key,&policy)&&names.size()==1);cases++;
 for(size_t size:{0,63,65}){reset();KeyBuffer bad(size);assert(!installKey("/data",options,bad,&policy)&&adds==0);cases++;}
 reset();search_error=EACCES;assert(!installKey("/data",options,key,&policy)&&adds==0);cases++;
 reset();ring_exists=false;assert(!installKey("/data",options,key,&policy)&&adds==0&&ring_adds==0);cases++;
 for(int fail=1;fail<=3;fail++){reset();assert(installKey("/data",options,key,&policy));unlink_fail=fail;assert(!evictKey("/data",policy)&&names.size()==1&&unlinks==3&&drops==1);cases++;}
 reset();assert(installKey("/data",options,key,&policy));search_error=EACCES;assert(!evictKey("/data",policy)&&names.size()==3&&drops==0);cases++;
 reset();assert(installKey("/data",options,key,&policy));drop_ok=false;assert(!evictKey("/data",policy)&&names.empty()&&drops==1);cases++;
 reset();policy.options=options;policy.key_raw_ref="short";assert(!evictKey("/data",policy)&&drops==0);cases++;
 assert(zeroed>64);
#else
 reset();assert(!installKey("/data",options,key,&policy)&&adds==0&&searches==0);cases++;
#endif
 std::cout<<"passed_cases="<<cases<<"\n";return 0;
}
'''
descriptor=hashlib.sha512(hashlib.sha512(bytes(range(64))).digest()).digest()[:8].hex();main=main.replace('EXPECTED_DESCRIPTOR',descriptor)
program=header+abi+functions+'\n#ifdef GTA3XLWIFI_LEGACY_FSCRYPT\n'+setup+'\n#endif\n'+main
program=program.replace('#include <iomanip>','#include <iomanip>\n#include <iostream>')
(a.output/'fixture.cpp').write_text(program);results=[]
for enabled in [False,True]:
 exe=a.output/('legacy' if enabled else 'modern')
 cmd=[str(compiler),'--driver-mode=g++','-std=gnu++17','--ld-path='+str(linker),'-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-const-variable','-Wno-deprecated-declarations','-fsanitize=address,undefined',*(['-DGTA3XLWIFI_LEGACY_FSCRYPT'] if enabled else []),'-I'+str(keyutils/'include'),'-I'+str(boringssl),str(a.output/'fixture.cpp'),str(lib),'-lpthread','-ldl','-o',str(exe)]
 result=subprocess.run(cmd,capture_output=True,text=True);(a.output/(exe.name+'-compile.log')).write_text(result.stdout+result.stderr);assert result.returncode==0,result.stderr
 result=subprocess.run([str(exe)],capture_output=True,text=True,env=dict(os.environ,UBSAN_OPTIONS='halt_on_error=1'));(a.output/(exe.name+'.log')).write_text(result.stdout+result.stderr);assert result.returncode==0 and not result.stderr,result.stdout+result.stderr
 results.append({'legacy_profile_enabled':enabled,'command':cmd,'stdout':result.stdout})
inputs=[kernel_header,compiler,linker,vold,init,bpf,fsheader,buf,lib,Path(__file__),keyutils/'keyutils.cpp',keyutils/'include/keyutils.h']
(a.output/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'results':results,'descriptor_sha512_oracle':descriptor,'inputs_sha256':{str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in inputs},'samsung_uapi_payload_layout_matches_android17':True,'no_real_keyring_syscalls':True,'actual_key_material_accessed':False,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print('PASS: typed real wrapper + init/vold bodies, modern and legacy profiles, independent descriptor digest and failure controls')
