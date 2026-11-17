#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute exact native CLAT verification and Rust flag-bootstrap bodies with explicit host boundaries.

Filesystem permissions/BPF syscalls/properties and storage-manager operations are
fixtures; production control flow is extracted unchanged. This is not device or
packet-translation validation. Both original failures must be reproduced first.
"""
from pathlib import Path
import argparse,hashlib,json,subprocess,fcntl
p=argparse.ArgumentParser();p.add_argument('--composition',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();C=a.composition;O=a.output;assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir()
T=Path('/srv/android/src/lineage-24.0-arm64');inputs={};sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):inputs[str(p)]=sha(p);return p.read_text()
def run(cmd):
 x=subprocess.run(list(map(str,cmd)),capture_output=True,text=True);assert x.returncode==0,(cmd,x.stdout,x.stderr);return x.stdout
native_prefix=r'''
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdarg>
struct Fatal{};
static void host_abort(){throw Fatal{};}
struct Expected {mode_t mode;uid_t uid;gid_t gid;std::string context;};
static std::map<std::string,Expected> expected;
static bool legacy,missingBpf;static std::string failure;static int fault,calls,bpfCalls,logs;
static uid_t host_getuid(){return 1000;}
static int host_lstat(const char*p,struct stat*s){calls++;auto v=expected.at(p);if((missingBpf&&std::string(p).find("/sys/fs/bpf")==0)||(p==failure&&fault==1)){errno=ENOENT;return -1;}s->st_mode=v.mode;s->st_uid=v.uid;s->st_gid=v.gid;if(p==failure){if(fault==2)s->st_mode^=1;if(fault==3)s->st_uid++;if(fault==4)s->st_gid++;}return 0;}
static ssize_t host_lgetxattr(const char*p,const char*,void*b,size_t n){if(p==failure&&fault==5){errno=EACCES;return -1;}std::string c=expected.at(p).context;if(p==failure&&fault==6)c="wrong";assert(c.size()+1<=n);memcpy(b,c.c_str(),c.size()+1);return c.size()+1;}
static int host_close(int fd){assert(fd==99);return 0;}
static void host_log(const char*,...){logs++;}
#define ALOGE(...) host_log(__VA_ARGS__)
#define lstat host_lstat
#define lgetxattr host_lgetxattr
#define close host_close
#define getuid host_getuid
#define abort host_abort
#define AID_ROOT 0
#define AID_SYSTEM 1000
#define AID_CLAT 1029
namespace android::base {static bool GetBoolProperty(const char*k,bool d){assert(std::string(k)=="ro.gta3xlwifi.legacy_networking"&&!d);return legacy;}}
namespace android::modules::sdklevel {static bool IsAtLeastT(){return true;}static bool IsAtLeastU(){return true;}}
namespace android::bpf {static int get(const char*p){bpfCalls++;if(missingBpf||(p==failure&&fault==7)){errno=EACCES;return -1;}return 99;}static int retrieveProgram(const char*p){return get(p);}static int mapRetrieveRO(const char*p){return get(p);}static int mapRetrieveLocklessRW(const char*p){return get(p);}}
'''
native_suffix=r'''
} // android
static int cases;
static void check(bool b){assert(b);cases++;}
static bool attempt(){android::fatal=false;calls=bpfCalls=logs=0;try{android::verifyClatPerms();return true;}catch(Fatal&){return false;}}
int main(int argc,char**argv){assert(argc==2);bool original=std::string(argv[1])=="original";
auto add=[](std::string p,mode_t m,uid_t u,gid_t g,std::string c){expected[p]={m,u,g,"u:object_r:"+c+":s0"};};
add(android::kClatdDir,S_IFDIR|0750,1029,1000,"system_file");add(android::kClatdBin,S_IFREG|S_ISUID|S_ISGID|0755,1029,1029,"clatd_exec");
add("/sys/fs/bpf",S_IFDIR|S_ISVTX|0777,0,0,"fs_bpf");add("/sys/fs/bpf/net_shared",S_IFDIR|01777,0,0,"fs_bpf_net_shared");
for(std::string p:{"prog_clatd_schedcls_egress4_clat_rawip","prog_clatd_schedcls_ingress6_clat_rawip","prog_clatd_schedcls_ingress6_clat_ether","map_clatd_clat_egress4_map","map_clatd_clat_ingress6_map"})add("/sys/fs/bpf/net_shared/"+p,S_IFREG|(p.find("prog_")==0?0440:0660),0,1000,"fs_bpf_net_shared");
legacy=true;missingBpf=true;check(attempt()==!original);check(original?bpfCalls==5:bpfCalls==0);if(original){puts("original_native_abort_reproduced");return 0;}
check(calls==2&&logs==0);missingBpf=false;
for(bool l:{false,true}){legacy=l;failure="";fault=0;check(attempt());check(calls==(l?2:9)&&bpfCalls==(l?0:5));for(auto&[p,v]:expected){if(l&&p.find("/sys/fs/bpf")==0)continue;failure=p;for(fault=1;fault<=6;fault++)check(!attempt());if(!l&&p.find("/sys/fs/bpf/net_shared/")==0){fault=7;check(!attempt());}}}
legacy=false;missingBpf=true;failure="";fault=0;check(!attempt()&&bpfCalls==5);printf("native_verification_cases=%d\n",cases);}
'''
native='packages/modules/Connectivity/service/jni/com_android_server_connectivity_ClatCoordinator.cpp'
for variant,label in [('baseline','original'),('files','fixed')]:
 s=read(C/variant/native);start=s.index('namespace android {');end=s.index('#undef V\n',start)+len('#undef V\n');f=O/(label+'.cpp');f.write_text(native_prefix+s[start:end]+native_suffix)
 run(['g++','-std=c++17','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=undefined','-fno-sanitize-recover=all',f,'-o',O/label]);out=run([O/label,label]);(O/(label+'-native.log')).write_text(out)
rust_prefix=r'''
#![allow(dead_code,unused_parens)]
use std::path::PathBuf;
macro_rules! debug {($($arg:tt)*) => {{}}}
#[derive(Debug)] enum AconfigdError {FailToGetFileMetadata{file:String,errmsg:std::io::Error},FailToReadSystemProperty{name:String,errmsg:String},Storage(String)}
mod rustutils {pub mod android {pub mod system_properties {pub fn read(_: &str)->Result<Option<String>,String>{let s=std::env::var("HOST_FSYNC").unwrap();if s=="error"{Err(s)}else{Ok(Some(s))}}}}}
#[derive(Default)] struct Store {initialized:Vec<String>,applied:Vec<String>,sync:Vec<bool>,fail:String}
impl Store {
 fn add_or_update_container_storage_files(&mut self,c:&str,_:&PathBuf,_:&PathBuf,v:&PathBuf,_:&PathBuf)->Result<(),AconfigdError>{if std::fs::read(v).unwrap()[0]==255{return Err(AconfigdError::Storage("corrupt".into()));}self.initialized.push(c.into());Ok(())}
 fn write_persist_storage_records_to_file(&self,_:&str,_:&str,_:&PathBuf)->Result<(),AconfigdError>{Ok(())}
 fn apply_staged_ota_flags(&self)->Result<(),AconfigdError>{if self.fail=="ota"{Err(AconfigdError::Storage("ota".into()))}else{Ok(())}}
 fn apply_all_staged_overrides(&mut self,c:&str,f:bool)->Result<(),AconfigdError>{if !self.initialized.iter().any(|v|v==c)||self.fail==c{return Err(AconfigdError::Storage(c.into()));}self.applied.push(c.into());self.sync.push(f);Ok(())}
}
#[derive(Default)] struct Daemon {root:PathBuf,storage_manager:Store,build_fingerprint:String,security_patch:String,persist_storage_records:PathBuf}
impl Daemon {
'''
rust_suffix=r'''
}
fn main(){let args:Vec<_>=std::env::args().collect();let original=args[1]=="original";let root=PathBuf::from(&args[2]);let names=["system","system_ext","product","vendor"];let mut cases=0;
for mask in 0..16 {for fsync in ["on","off"]{for incomplete in 0..6 {if root.exists(){std::fs::remove_dir_all(&root).unwrap();}let mut desired=Vec::new();for (i,c) in names.iter().enumerate(){let d=root.join(c).join("etc/aconfig");std::fs::create_dir_all(&d).unwrap();if mask&(1<<i)==0{continue;}for (j,n) in ["package.map","flag.map","flag.val","flag.info"].iter().enumerate(){if *c=="vendor"&&incomplete==j+1{continue;}std::fs::write(d.join(n),if *c=="vendor"&&incomplete==5&&*n=="flag.val"{vec![]}else{vec![1]}).unwrap();}if *c!="vendor"||incomplete==0{desired.push(c.to_string());}}
std::env::set_var("HOST_FSYNC",fsync);let mut d=Daemon{root:root.clone(),..Default::default()};let result=d.initialize_platform_storage();if original{if mask==7&&incomplete==0 {assert!(result.is_err());println!("original_optional_vendor_failure_reproduced");std::fs::remove_dir_all(&root).unwrap();return;}continue;}assert!(result.is_ok(),"{:?}",result);assert_eq!(d.storage_manager.initialized,desired);assert_eq!(d.storage_manager.applied,desired);assert!(d.storage_manager.sync.iter().all(|f|*f==(fsync=="on")));cases+=1;}}}
if original{panic!("original failure not reached");}
// Registered corruption, failed override, staged OTA errors and property errors must propagate.
for failure in ["system","vendor","ota","property","corrupt"]{for c in names {let d=root.join(c).join("etc/aconfig");std::fs::create_dir_all(&d).unwrap();for n in ["package.map","flag.map","flag.val","flag.info"]{std::fs::write(d.join(n),[if failure=="corrupt"&&c=="vendor"{255}else{1}]).unwrap();}}
std::env::set_var("HOST_FSYNC",if failure=="property"{"error"}else{"on"});let mut d=Daemon{root:root.clone(),..Default::default()};d.storage_manager.fail=failure.into();assert!(d.initialize_platform_storage().is_err());cases+=1;}
std::fs::remove_dir_all(&root).unwrap();println!("flag_bootstrap_cases={cases}");}
'''
rust='packages/modules/ConfigInfrastructure/aconfigd/src/aconfigd.rs';compiler=T/'prebuilts/rust-toolchain/linux-x86/1.93.1/bin/rustc';inputs[str(compiler)]=sha(compiler)
for variant,label in [('baseline','original'),('files','fixed')]:
 s=read(C/variant/rust);start=s.index('    pub fn initialize_platform_storage(');end=s.index('    /// Initialize mainline storage files',start);body=s[start:end];needle='PathBuf::from("/".to_string() + container + "/etc/aconfig")';assert body.count(needle)==1
 # Explicit host filesystem-root boundary, no control-flow rewrite.
 body=body.replace(needle,'self.root.join(container).join("etc/aconfig")');f=O/(label+'.rs');f.write_text(rust_prefix+body+rust_suffix)
 run([compiler,'--edition=2021',f,'-o',O/(label+'-flags')]);out=run([O/(label+'-flags'),label,O/'fs']);(O/(label+'-flags.log')).write_text(out)
inputs[str(Path(__file__).resolve())]=sha(Path(__file__).resolve())
(O/'report.json').write_text(json.dumps(dict(passed=True,scope=__doc__,source_sha256={n:v['after'] for n,v in json.loads((C/'selection.json').read_text())['files'].items()},inputs_sha256=inputs,original_native_abort_reproduced=True,original_optional_vendor_failure_reproduced=True,native_verification_cases=int((O/'fixed-native.log').read_text().split('=')[1]),flag_bootstrap_cases=int((O/'fixed-flags.log').read_text().split('=')[1]),BPF_readiness_synthesized=False,common_daemon_permission_checks_retained=True,modern_BPF_checks_retained=True,hardware_tested=False),indent=2)+'\n');print((O/'fixed-native.log').read_text().strip());print((O/'fixed-flags.log').read_text().strip())
