#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check private immutable creator identity helpers and exact socket hook sites.

Actual new C bodies plus existing kernel BPF UID helper body, with credential,
namespace and object-copy fixtures. A17 source storage assignment/no-clone map
contract is checked. No sockets, permissions, storage map or readiness execute.
"""
import argparse,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','reference-kernel','android-source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();S=a.source.resolve();K=a.reference_kernel.resolve();A=a.android_source.resolve();O=a.output.resolve();assert not O.exists();O.mkdir(parents=True)
helper=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('extract',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
core=S/'net/core/sock.c';header=S/'include/net/sock.h';h=header.read_text();text=core.read_text();old=K/'kernel/bpf/helpers.c';reference=A/'packages/modules/Connectivity/bpf/progs/netd.c';bpf_headers=[A/'packages/modules/Connectivity/bpf/progs/include/bpf_helpers.h',A/'system/bpf/include/bpf/bpf_helpers.h']
assert 'sk_gta_creator_uid' in h and 'sk_gta_creator_valid' in h
for name in ['net/ipv4/af_inet.c','net/ipv6/af_inet6.c']:
 t=(S/name).read_text();needle='\tsock_init_data(sock, sk);\n\tgta3xlwifi_socket_creator_init(sk, kern);';assert t.count(needle)==1 and t.count('gta3xlwifi_socket_creator_init(')==1
assert text.count('sock_copy(newsk, sk);\n\t\tgta3xlwifi_socket_creator_clone_reset(newsk);')==1
for name in ['sock_copy','sock_init_data']:assert m.extract(text,name)==m.extract((K/'net/core/sock.c').read_text(),name)
assert m.extract(h,'sock_graft')==m.extract((K/'include/net/sock.h').read_text(),'sock_graft')
assert 'DEFINE_BPF_SK_STORAGE(sk_storage, SkStorageValue)' in reference.read_text() and 'sks->uid = gid_uid;' in m.extract(reference.read_text(),'inet_socket_create')
for p in bpf_headers:
 t=p.read_text();assert 'BPF_F_CLONE' not in t
 macro=t[t.index('#define DEFINE_BPF_SK_STORAGE(the_map,'):];macro=macro.split('\n\n',1)[0];assert re.search(r',\s*0\)\s*$',macro)
actual='\n'.join(m.extract(text,n) for n in ['gta3xlwifi_socket_creator_init','gta3xlwifi_socket_creator_clone_reset'])
oracle=m.extract(old.read_text(),'bpf_get_current_uid_gid');start=oracle.index('{');oracle='static u64 reference_uid_gid(void)\n'+oracle[start:]
code=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint64_t u64;typedef uint32_t kuid_t;typedef uint32_t kgid_t;
struct user_namespace{int id;};static struct user_namespace init_user_ns={0};
struct task_struct{int unused;};static struct task_struct task;static struct task_struct* current=&task;
static uint32_t real_uid,real_gid;
static uint32_t current_uid(void){return real_uid;}
static void current_uid_gid(kuid_t* uid,kgid_t* gid){*uid=real_uid;*gid=real_gid;}
static uint32_t from_kuid(const struct user_namespace* ns,kuid_t uid){assert(ns==&init_user_ns);return uid;}
static uint32_t from_kgid(const struct user_namespace* ns,kgid_t gid){assert(ns==&init_user_ns);return gid;}
struct sock{uint32_t sk_uid,sk_gta_creator_uid;bool sk_gta_creator_valid;};
'''+actual+'\n'+oracle+r'''
static unsigned cases,comparisons;
#define T(x) do{assert(x);++cases;}while(0)
int main(void){
 const uint32_t uids[]={0,1,9999,10000,10001,65534,100001,110001,0x7fffffff,0xffffffff};
 const uint32_t gids[]={0,1000,0xffffffff},inodes[]={0,10001,20001,0xffffffff};
 for(unsigned kernel=0;kernel<2;kernel++)for(unsigned u=0;u<10;u++)for(unsigned g=0;g<3;g++)for(unsigned i=0;i<4;i++){
  real_uid=uids[u];real_gid=gids[g];struct sock sk={inodes[i],123,true};uint32_t expected=kernel?0:(uint32_t)reference_uid_gid();
  gta3xlwifi_socket_creator_init(&sk,kernel);assert(sk.sk_uid==inodes[i]&&sk.sk_gta_creator_uid==expected&&sk.sk_gta_creator_valid==!kernel);++comparisons;
  // Model current UID, inode ownership/graft and FD recipient changes. None is
  // an initialization hook, so the captured identity remains immutable.
  sk.sk_uid=54321;real_uid=12345;assert(sk.sk_gta_creator_uid==expected&&sk.sk_gta_creator_valid==!kernel);++comparisons;
  struct sock clone;memcpy(&clone,&sk,sizeof(clone));gta3xlwifi_socket_creator_clone_reset(&clone);
  assert(!clone.sk_gta_creator_valid&&clone.sk_gta_creator_uid==0&&clone.sk_uid==54321);++comparisons;
  assert(sk.sk_gta_creator_uid==expected&&sk.sk_gta_creator_valid==!kernel);++comparisons;
 }
 struct sock sk={777,0,true};gta3xlwifi_socket_creator_clone_reset(&sk);T(!sk.sk_gta_creator_valid&&sk.sk_uid==777);gta3xlwifi_socket_creator_clone_reset(&sk);T(!sk.sk_gta_creator_valid&&sk.sk_uid==777);
 printf("passed_cases=%u comparisons=%u\n",cases,comparisons);
}
'''
(O/'test.c').write_text(code);cmd=['cc','-std=gnu11','-Wall','-Wextra','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all',str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr
env=os.environ.copy();env['UBSAN_OPTIONS']='halt_on_error=1';x=subprocess.run([str(O/'test')],capture_output=True,text=True,env=env,timeout=30);(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.returncode,x.stdout,x.stderr)
match=re.fullmatch(r'passed_cases=(\d+) comparisons=(\d+)\n',x.stdout);assert match and int(match[2])==960
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),helper,core,header,old,reference,*bpf_headers,O/'test.c',*[S/n for n in ['net/ipv4/af_inet.c','net/ipv6/af_inet6.c']],K/'net/core/sock.c',K/'include/net/sock.h']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'passed_cases':int(match[1]),'identity_lifecycle_comparisons':int(match[2]),'exact_inet4_inet6_clone_hook_contracts':True,'socket_init_copy_graft_functions_unchanged':True,'stderr':x.stderr,'command':cmd,'inputs_sha256':{str(x.resolve()):sha(x) for x in paths},'modern_helper_reference':'https://raw.githubusercontent.com/torvalds/linux/v6.6/kernel/bpf/helpers.c','hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip()+'; actual creator init/reset helpers and exact hook contracts, fatal UBSan fixtures')
