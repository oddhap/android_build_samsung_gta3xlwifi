#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run actual modified OpenBSD C bodies with real kernel entropy and explicit syscall fault fixtures."""
import argparse,hashlib,json,shutil,signal,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--candidate',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();O=a.output.resolve();C=a.candidate.resolve();assert not O.exists();O.mkdir(parents=True)
inc=O/'include/async_safe';inc.mkdir(parents=True)
(inc/'log.h').write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <stdarg.h>\n__attribute__((noreturn)) static inline void async_safe_fatal(const char* f, ...) { va_list a; va_start(a,f); vfprintf(stderr,f,a); va_end(a); abort(); }\n')
H=C/'files/bionic/libc/upstream-openbsd/android/include/arc4random.h';S=C/'files/bionic/libc/upstream-openbsd/lib/libc/crypt/arc4random.c';shutil.copyfile(H,O/'include/arc4random.h');shutil.copyfile(C/'chacha_private.h',O/'include/chacha_private.h')
h=O/'harness.c';h.write_text(r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdatomic.h>
extern uint32_t tested_arc4random(void);
extern void tested_arc4random_buf(void*,size_t);
extern void arc4random_mutex_lock(void);
extern void arc4random_mutex_unlock(void);
static const char* mode;
static _Atomic unsigned calls;
void* fixture_mmap(void* a,size_t n,int p,int f,int fd,off_t off) {
 if (!strcmp(mode,"map-oom")) {errno=ENOMEM;return MAP_FAILED;}
 return mmap(a,n,p,f,fd,off);
}
int fixture_madvise(void* p,size_t n,int advice) {
 assert(advice==MADV_WIPEONFORK);
 if (!strcmp(mode,"native")) return madvise(p,n,advice);
 errno=!strcmp(mode,"probe-denied")?EPERM:EINVAL;return -1;
}
ssize_t fixture_getrandom(void* p,size_t n,unsigned flags) {
 assert(flags==0 && n>0 && n<=256);
 unsigned c=atomic_fetch_add(&calls,1);
 if (!strcmp(mode,"entropy-eio")) {errno=EIO;return -1;}
 if (!strcmp(mode,"entropy-zero")) return 0;
 if (!strcmp(mode,"eintr") && c<3) {errno=EINTR;return -1;}
 if (!strcmp(mode,"short") && n>7)n=7;
 return syscall(SYS_getrandom,p,n,flags);
}
static void* thread(void* ignored) {
 (void)ignored;
 for(int i=0;i<128;i++){unsigned char a[80];memset(a,0xa5,sizeof(a));tested_arc4random_buf(a+8,64);for(int k=0;k<8;k++)assert(a[k]==0xa5 && a[72+k]==0xa5);(void)tested_arc4random();}
 return NULL;
}
int main(int argc,char** argv) {
 assert(argc==2);mode=argv[1];assert(pthread_atfork(arc4random_mutex_lock,arc4random_mutex_unlock,arc4random_mutex_unlock)==0);
 size_t sizes[]={0,1,4,32,255,256,257,1000,65536,1048576};
 for(unsigned i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++) {
  size_t n=sizes[i];unsigned char* p=malloc(n+16);assert(p);memset(p,0xa5,n+16);tested_arc4random_buf(p+8,n);
  for(int k=0;k<8;k++)assert(p[k]==0xa5 && p[n+8+k]==0xa5);
  if(n>=32){unsigned char diff=0;for(size_t k=0;k<n;k++)diff|=p[8+k]^0xa5;assert(diff);}
  free(p);
 }
 pthread_t tids[8];for(int i=0;i<8;i++)assert(pthread_create(tids+i,NULL,thread,NULL)==0);for(int i=0;i<8;i++)assert(pthread_join(tids[i],NULL)==0);
 for(int i=0;i<32;i++) {
  int fds[2];assert(pipe(fds)==0);pid_t pid=fork();assert(pid>=0);
  if(!pid){close(fds[0]);unsigned char b[32];tested_arc4random_buf(b,32);assert(write(fds[1],b,32)==32);_exit(0);}
  close(fds[1]);unsigned char a[32],b[32];tested_arc4random_buf(a,32);size_t got=0;while(got<32){ssize_t n=read(fds[0],b+got,32-got);assert(n>0);got+=n;}close(fds[0]);int status;assert(waitpid(pid,&status,0)==pid && status==0);assert(memcmp(a,b,32));
 }
 if(!strcmp(mode,"native"))assert(calls==0);else assert(calls>1000);
 printf("PASS mode=%s sizes=10 threads=8x128 forks=32 kernel_entropy_calls=%u\n",mode,(unsigned)calls);
 return 0;
}
''')
obj=O/'arc.o';exe=O/'test';cmd=['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-D_GNU_SOURCE','-DPR_SET_VMA=0x53564d41','-DPR_SET_VMA_ANON_NAME=0','-DDEF_WEAK(x)=','-Darc4random=tested_arc4random','-Darc4random_buf=tested_arc4random_buf','-Dgetrandom=fixture_getrandom','-Dmadvise=fixture_madvise','-Dmmap=fixture_mmap','-I'+str(O/'include'),'-c',str(S),'-o',str(obj)]
r=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
r=subprocess.run(['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',str(h),str(obj),'-pthread','-o',str(exe)],capture_output=True,text=True);assert r.returncode==0,r.stderr
results=[]
for mode in ['native','legacy','short','eintr','entropy-eio','entropy-zero','probe-denied','map-oom']:
 r=subprocess.run([str(exe),mode],capture_output=True,text=True,timeout=30);expected=0 if mode in ['native','legacy','short','eintr'] else -signal.SIGABRT
 assert r.returncode==expected,(mode,r.returncode,r.stdout,r.stderr)
 results.append({'mode':mode,'exit_code':r.returncode,'expected_exit_code':expected,'stdout':r.stdout,'stderr':r.stderr});print(mode,'PASS',flush=True)
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'source_sha256':{str(f):sha(f) for f in [S,H,C/'chacha_private.h']},'tests':results,'compile_command':cmd,'real_kernel_getrandom_used':True,'short_EINTR_fork_thread_and_fail_closed_checked':True,'actual_Android_TWRP_execution_proven':False,'flash_ready':False},indent=2)+'\n')
