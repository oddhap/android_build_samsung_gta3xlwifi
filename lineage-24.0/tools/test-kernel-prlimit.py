#!/usr/bin/env python3
"""Actual prlimit DAC, LSM dispatch, SELinux and syscall bodies with fixtures.

Credential/RCU/list/AVC/task/user-memory backends are sequential fixtures. ABI
callsite assertions show native/compat share the syscall; no ARM userspace,
real concurrency, actual resource updates or hardware execution is performed.
"""
import argparse,hashlib,importlib.util,json,re,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ['kernel','before','modern','report']:p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();assert not a.report.exists()
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
func=module('extract','test-netlink-xperm24.py').function;table=module('surface','audit-kernel-policy-surface.py').table
rel='security/selinux/';old=table(a.before/(rel+'include/classmap.h'),'clang');new=table(a.kernel/(rel+'include/classmap.h'),'clang');assert list(old)==list(new)
for name in old:assert new[name]==old[name]+(['getrlimit'] if name=='process' else [])
system=(a.kernel/'kernel/sys.c').read_text();before=(a.before/'kernel/sys.c').read_text()
assert func(system,'do_prlimit')==func(before,'do_prlimit')
assert func(system,'check_prlimit_permission')==func((a.modern/'kernel/sys.c').read_text(),'check_prlimit_permission')
for path in ['arch/arm64/include/asm/unistd32.h','include/uapi/asm-generic/unistd.h']:
 s=(a.kernel/path).read_text();assert '__SYSCALL(__NR_prlimit64, sys_prlimit64)' in s;assert s==(a.before/path).read_text()
start=system.index('SYSCALL_DEFINE4(prlimit64,');end=system.index('\nSYSCALL_DEFINE2(setrlimit,',start)
syscall=system[start:end];syscall=syscall[syscall.index('{'):]
api=(a.kernel/'include/linux/security.h').read_text();lsm=(a.kernel/'include/linux/lsm_hooks.h').read_text();core=(a.kernel/'security/security.c').read_text();hooks=(a.kernel/(rel+'hooks.c')).read_text()
assert 'LSM_HOOK_INIT(task_prlimit, selinux_task_prlimit)' in hooks
assert 'int (*task_prlimit)(const struct cred *cred, const struct cred *tcred,' in lsm
assert 'struct list_head task_prlimit;' in lsm
assert 'int security_task_prlimit(const struct cred *cred, const struct cred *tcred,' in api
stub=func(api,'security_task_prlimit');assert 'return 0;' in stub
macro=core[core.index('#define call_int_hook('):core.index('\n\n',core.index('#define call_int_hook('))]
init=re.search(r'\t.task_prlimit =\s*LIST_HEAD_INIT\(security_hook_heads.task_prlimit\),',core)[0]
register=lsm[lsm.index('#define LSM_HOOK_INIT('):lsm.index('\n\n',lsm.index('#define LSM_HOOK_INIT('))]
structlist=re.search(r'struct security_hook_list \{.*?\n};',lsm,re.S)[0]
parts=[r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint32_t u32;
''']
for key in ['LSM_PRLIMIT_READ','LSM_PRLIMIT_WRITE']:
 parts.append(re.search(r'^#define '+key+r' .*$',api,re.M)[0])
parts+=['#define PROCESS__SETRLIMIT (1U<<'+str(new['process'].index('setrlimit'))+')',
        '#define PROCESS__GETRLIMIT (1U<<'+str(new['process'].index('getrlimit'))+')',
        '#define SECCLASS_PROCESS '+str(list(new).index('process')+1),r'''
#define CAP_SYS_RESOURCE 24
struct user_namespace {int unused;};static struct user_namespace user_ns;
struct cred {int uid,euid,suid,gid,egid,sgid;u32 sid;struct user_namespace *user_ns;};
static struct cred caller={100,100,100,200,200,200,42,&user_ns};
static struct cred target={100,100,100,200,200,200,84,&user_ns};
struct task_struct {struct cred *cred;int references;};
static struct task_struct actor={&caller,0},other={&target,0};
#define current (&actor)
static int rcu_depth,capable,integrity_error,avc_error;
static u32 denied;static unsigned avc_calls;
static void rcu_read_lock(void) {assert(!rcu_depth);rcu_depth=1;}
static void rcu_read_unlock(void) {assert(rcu_depth==1);rcu_depth=0;}
static const struct cred *current_cred(void) {return &caller;}
static const struct cred *__task_cred(struct task_struct *task) {assert(rcu_depth==1);return task->cred;}
#define uid_eq(a,b) ((a)==(b))
#define gid_eq(a,b) ((a)==(b))
static int ns_capable(struct user_namespace *ns,int cap) {assert(ns==&user_ns && cap==CAP_SYS_RESOURCE);return capable;}
static u32 cred_sid(const struct cred *cred) {return cred->sid;}
static int avc_has_perm(u32 s,u32 t,unsigned short c,u32 perms,void *ad) {
 assert(s==42 && t==84 && c==SECCLASS_PROCESS && ad==NULL && perms);
 avc_calls++;return perms&denied?avc_error:0;
}
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD_INIT(n) {&(n),&(n)}
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,__typeof__(*p),m);&(p)->m!=(h);p=container_of((p)->m.next,__typeof__(*p),m))
static void list_add_tail_rcu(struct list_head *node,struct list_head *head) {
 node->next=head;node->prev=head->prev;head->prev->next=node;head->prev=node;
}
union security_list_options {int (*task_prlimit)(const struct cred *cred,const struct cred *tcred,unsigned flags);};
''',structlist,r'''
struct security_hook_heads {struct list_head task_prlimit;};
static struct security_hook_heads security_hook_heads={
''',init,'};',register,func(lsm,'security_add_hooks'),r'''
static int security_integrity_current(void) {return integrity_error;}
''',macro,func(hooks,'selinux_task_prlimit'),r'''
static struct security_hook_list selinux_hooks[]={LSM_HOOK_INIT(task_prlimit,selinux_task_prlimit)};
''',func(core,'security_task_prlimit'),func(system,'check_prlimit_permission'),r'''
struct rlimit64 {uint64_t rlim_cur,rlim_max;};
struct rlimit {unsigned long rlim_cur,rlim_max;};
static int copyin_error,copyout_error,missing_task,resource_error,resource_calls;
static unsigned last_flags;
static int copy_from_user(void *dest,const void *src,size_t size) {if(copyin_error)return 1;memcpy(dest,src,size);return 0;}
static int copy_to_user(void *dest,const void *src,size_t size) {if(copyout_error)return 1;memcpy(dest,src,size);return 0;}
static void rlim64_to_rlim(const struct rlimit64 *src,struct rlimit *dst) {dst->rlim_cur=src->rlim_cur;dst->rlim_max=src->rlim_max;}
static void rlim_to_rlim64(const struct rlimit *src,struct rlimit64 *dst) {dst->rlim_cur=src->rlim_cur;dst->rlim_max=src->rlim_max;}
static struct task_struct *find_task_by_vpid(int pid) {assert(pid==1 && rcu_depth==1);return missing_task?NULL:&other;}
static void get_task_struct(struct task_struct *task) {assert(rcu_depth==1);task->references++;}
static void put_task_struct(struct task_struct *task) {assert(rcu_depth==0 && task->references==1);task->references--;}
static int do_prlimit(struct task_struct *task,unsigned resource,struct rlimit *new,struct rlimit *old) {
 assert(rcu_depth==0 && task->references==1 && resource==7);resource_calls++;
 last_flags=(new?LSM_PRLIMIT_WRITE:0)|(old?LSM_PRLIMIT_READ:0);
 if(old){old->rlim_cur=11;old->rlim_max=22;}
 return resource_error;
}
static int fixture_prlimit64(int pid,unsigned resource,const struct rlimit64 *new_rlim,struct rlimit64 *old_rlim)
''',syscall,r'''
int main(void) {
 assert(security_hook_heads.task_prlimit.next==&security_hook_heads.task_prlimit);
 assert(security_hook_heads.task_prlimit.prev==&security_hook_heads.task_prlimit);
 security_add_hooks(selinux_hooks,1);
 assert(security_hook_heads.task_prlimit.next==&selinux_hooks[0].list);
 unsigned long direct=0,syscalls=0;
 for(unsigned self=0;self<2;self++)for(unsigned ids=0;ids<64;ids++)for(unsigned cap=0;cap<2;cap++)
 for(unsigned flags=0;flags<4;flags++)for(unsigned deny=0;deny<4;deny++)for(unsigned error=0;error<2;error++)
 for(unsigned integrity=0;integrity<2;integrity++) {
  target.euid=100+!!(ids&1);target.suid=100+!!(ids&2);target.uid=100+!!(ids&4);
  target.egid=200+!!(ids&8);target.sgid=200+!!(ids&16);target.gid=200+!!(ids&32);
  capable=cap;integrity_error=integrity?-EFAULT:0;avc_error=error?-ENOMEM:-EACCES;
  denied=(deny&1?PROCESS__GETRLIMIT:0)|(deny&2?PROCESS__SETRLIMIT:0);avc_calls=0;
  u32 requested=(flags&LSM_PRLIMIT_READ?PROCESS__GETRLIMIT:0)|(flags&LSM_PRLIMIT_WRITE?PROCESS__SETRLIMIT:0);
  int expected=self?0:ids&&!cap?-EPERM:integrity_error?integrity_error:requested&denied?avc_error:0;
  rcu_read_lock();int rc=check_prlimit_permission(self?current:&other,flags);rcu_read_unlock();
  assert(rc==expected && avc_calls==(unsigned)(!self&&(!ids||cap)&&!integrity&&flags));direct++;
 }
 target=caller;target.sid=84;capable=integrity_error=0;
 for(unsigned self=0;self<2;self++)for(unsigned read=0;read<2;read++)for(unsigned write=0;write<2;write++)
 for(unsigned input=0;input<2;input++)for(unsigned output=0;output<2;output++)for(unsigned missing=0;missing<2;missing++)
 for(unsigned err=0;err<2;err++)for(unsigned mac=0;mac<2;mac++) {
  struct rlimit64 from={33,44},to={0,0};copyin_error=input;copyout_error=output;
  missing_task=missing;resource_error=err?-EINVAL:0;resource_calls=0;denied=mac?~0U:0;avc_error=-EACCES;avc_calls=0;
  int expected=write&&input?-EFAULT:!self&&missing?-ESRCH:!self&&mac&&(read||write)?-EACCES:resource_error?resource_error:read&&output?-EFAULT:0;
  int rc=fixture_prlimit64(self?0:1,7,write?&from:NULL,read?&to:NULL);
  assert(rc==expected && rcu_depth==0 && actor.references==0 && other.references==0);
  int reached=!(write&&input)&&!(!self&&missing)&&!(!self&&mac&&(read||write));
  assert(resource_calls==reached);
  if(reached)assert(last_flags==((write?LSM_PRLIMIT_WRITE:0)|(read?LSM_PRLIMIT_READ:0)));
  if(!rc&&read)assert(to.rlim_cur==11 && to.rlim_max==22);syscalls++;
 }
 printf("PASS: %lu DAC/LSM/SELinux and %lu actual syscall fixture scenarios; initialized/registered real dispatch chain\n",direct,syscalls);
 return 0;
}
''']
with tempfile.TemporaryDirectory(prefix='prlimit-') as d:
 t=Path(d);(t/'test.c').write_text('\n'.join(parts))
 subprocess.run(['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=address,undefined',str(t/'test.c'),'-o',str(t/'test')],check=True)
 result=subprocess.run([str(t/'test')],check=True,capture_output=True,text=True);print(result.stdout,end='')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files=[a.kernel/x for x in ['kernel/sys.c','include/linux/security.h','include/linux/lsm_hooks.h','security/security.c',rel+'hooks.c',rel+'include/classmap.h','arch/arm64/include/asm/unistd32.h','include/uapi/asm-generic/unistd.h']]+[a.before/'kernel/sys.c',a.before/(rel+'include/classmap.h'),a.modern/'kernel/sys.c']
a.report.write_text(json.dumps({'passed':True,'scope':__doc__,'result':result.stdout.strip(),'existing_class_permission_ids_preserved':True,'original_do_prlimit_body_unchanged':True,'native_compat_share_sys_prlimit64':True,'initialized_and_registered_hook_chain_fixture':True,'runner_sha256':sha(Path(__file__)),'inputs_sha256':{str(f):sha(f) for f in files},'hardware_tested':False,'actual_resource_updates_or_live_concurrency_tested':False},indent=2)+'\n')
