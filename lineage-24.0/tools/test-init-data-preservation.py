#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile actual init recovery/mount dispatch bodies against synthetic effects.

Checks destructive-request rejection before bootloader writes/reboots. Does not
access a bootloader, recovery, mounted filesystem or real encryption key.
"""
import argparse, hashlib, json, os, shutil, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
src=a.source.read_text()
def function(signature):
 start=src.index(signature);begin=src.index('{',start);depth=1;pos=begin+1
 # These two functions contain no brace literals/comments; preserve exact bytes.
 while depth:
  depth += (src[pos]=='{')-(src[pos]=='}');pos+=1
 return src[start:pos]
body=function('static Result<void> reboot_into_recovery(')+'\n'+function('static Result<void> queue_fs_event(')
header=r'''
#include <cassert>
#include <iostream>
#include <string>
#include <vector>
struct Failure {template<class T> Failure& operator<<(const T&){return *this;}};
static Failure Error(){return {};}
template<class T> struct Result {bool good=true;Result()=default;Result(Failure):good(false){} bool ok()const{return good;}};
struct Logger {template<class T> Logger& operator<<(const T&){return *this;}};
#define LOG(x) Logger()
#define PLOG(x) Logger()
static bool micro=false,gsi=false,write_ok=true;
static unsigned writes,reboots,properties,events;
static std::vector<std::string> written;
static std::string prop,event;
static bool IsMicrodroid(){return micro;}
namespace android::gsi {static bool IsGsiRunning(){return ::gsi;}}
static bool write_bootloader_message(const std::vector<std::string>& o,std::string*){++writes;written=o;return write_ok;}
static void trigger_shutdown(const std::string& s){assert(s=="reboot,recovery");++reboots;}
static void SetProperty(const std::string& k,const std::string& v){assert(k=="ro.crypto.state");++properties;prop=v;}
struct ActionManager {static ActionManager& GetInstance(){static ActionManager a;return a;}void QueueEventTrigger(const std::string& s){++events;event=s;}};
enum {FS_MGR_MNTALL_DEV_NOT_ENCRYPTABLE=1,FS_MGR_MNTALL_DEV_NEEDS_RECOVERY=2,FS_MGR_MNTALL_DEV_FILE_ENCRYPTED=3,FS_MGR_MNTALL_DEV_IS_METADATA_ENCRYPTED=4,FS_MGR_MNTALL_DEV_NEEDS_METADATA_ENCRYPTION=5};
static void reset(){writes=reboots=properties=events=0;written.clear();prop.clear();event.clear();micro=gsi=false;write_ok=true;}
'''
tests=r'''
int main(){unsigned cases=0;
#ifdef GTA3XLWIFI_LEGACY_FSCRYPT
 constexpr bool legacy=true;
#else
 constexpr bool legacy=false;
#endif
 for(const auto& flag:std::vector<std::string>{"--wipe_data","--wipe_data_with_tpm_check","--wipe_cache","--prompt_and_wipe_data"}){
  for(int mode=0;mode<4;++mode){reset();micro=mode&1;write_ok=!(mode&2);
   auto r=reboot_into_recovery({"--reason=synthetic",flag});
   if(legacy){assert(!r.ok());assert(writes==0&&reboots==0);}
   else {assert(writes==(micro?0u:1u));assert(r.ok()==(micro||write_ok));assert(reboots==unsigned(micro||write_ok));}
   ++cases;
  }
 }
 for(auto options:std::vector<std::vector<std::string>>{{},{"--reason=manual"},{"--update_package=/cache/update.zip"},{"--reason=--wipe_data"}}){
  for(int mode=0;mode<4;++mode){reset();micro=mode&1;write_ok=!(mode&2);auto r=reboot_into_recovery(options);
   assert(r.ok()==(micro||write_ok));assert(writes==(micro?0u:1u));assert(reboots==unsigned(micro||write_ok));if(writes)assert(written==options);++cases;
  }
 }
 for(int code=-2;code<=6;++code){for(int isgsi=0;isgsi<2;++isgsi){reset();gsi=isgsi;auto r=queue_fs_event(code);
  if(code==2){assert(r.ok()==(!legacy&&!gsi));assert(writes==unsigned(!legacy&&!gsi));assert(reboots==unsigned(!legacy&&!gsi));assert(properties==0&&events==0);}
  else if(code==1||(code>=3&&code<=5)){assert(r.ok());assert(properties==1&&events==1);assert(prop==(code==1?"unsupported":"encrypted"));assert(event=="nonencrypted");assert(writes==0&&reboots==0);}
  else {assert(!r.ok());assert(properties==0&&events==0&&writes==0&&reboots==0);}
  ++cases;
 }}
 std::cout<<"passed_cases="<<cases<<"\n";
}
'''
compiler=shutil.which('clang++') or shutil.which('c++');assert compiler
results=[]
for legacy in [False,True]:
 name='legacy' if legacy else 'current';cpp=a.output/(name+'.cpp');exe=a.output/name;cpp.write_text(header+'\n'+body+'\n'+tests)
 cmd=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all',str(cpp),'-o',str(exe)]
 if legacy:cmd.insert(1,'-DGTA3XLWIFI_LEGACY_FSCRYPT')
 build=subprocess.run(cmd,capture_output=True,text=True);assert build.returncode==0,build.stderr
 env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1'
 r=subprocess.run([str(exe)],capture_output=True,text=True,env=env);assert r.returncode==0 and not r.stderr and r.stdout=='passed_cases=50\n',(r.returncode,r.stdout,r.stderr)
 results.append({'profile':name,'command':cmd,'passed_cases':50,'stderr':r.stderr})
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
report={'passed':True,'scope':__doc__,'inputs_sha256':{str(a.source.resolve()):sha(a.source),str(Path(__file__).resolve()):sha(Path(__file__))},'results':results,'hardware_tested':False,'flash_ready':False}
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: 100 real-body init dispatch cases; fatal UBSan, no real storage/reboot effects')
