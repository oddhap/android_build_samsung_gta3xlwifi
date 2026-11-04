#!/usr/bin/env python3
"""Actual perf LSM/label, trace permission, IO wrappers and allocation/free tails.

Memory, credentials, policy, PMU, RCU/IRQ/context, filter/BPF and ring-buffer
backends are fixtures. Full syscall/context/hardware scheduling is not executed;
mmap and allocation run explicitly delimited production fragments.
"""
import argparse,hashlib,importlib.util,json,re,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ['kernel','before','report']:p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();assert not a.report.exists()
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
extractor=module('extract','test-netlink-xperm24.py');func=extractor.function;surface=module('surface','audit-kernel-policy-surface.py');table=surface.table
# Regression for the prose/quoted-brace parser error found during perf staging.
for code,expected in [('/* target() prose */\nstatic int other(void){return 0;}\nstatic int target(void){return 1;}','return 1'),('static int target(void);\nstatic int target(void){return 2;}','return 2'),('static struct thing *\ntarget(void){return 0;}','struct thing'),('static int target(void){const char *s="} // data";return 3;}','return 3')]:assert expected in func(code,'target')
rel='security/selinux/';old=table(a.before/(rel+'include/classmap.h'),'clang');new=table(a.kernel/(rel+'include/classmap.h'),'clang');assert list(new)[:-1]==list(old) and list(new)[-1]=='perf_event'
for n in old:assert old[n]==new[n]
core=(a.kernel/'kernel/events/core.c').read_text();legacy_core=(a.before/'kernel/events/core.c').read_text();header=(a.kernel/'include/linux/perf_event.h').read_text();legacy_header=(a.before/'include/linux/perf_event.h').read_text()
for n in ['perf_paranoid_any','perf_paranoid_cpu','perf_paranoid_kernel','perf_paranoid_tracepoint_raw']:assert func(header,n)==func(legacy_header,n)
assert func(core,'perf_compat_ioctl')==func(legacy_core,'perf_compat_ioctl')
assert func(core,'perf_mmap').lstrip().startswith('static int perf_mmap(')
assert core.count('security_perf_event_open(PERF_SECURITY_CPU)')==1 and core.count('security_perf_event_open(PERF_SECURITY_KERNEL)')==2 and core.count('security_perf_event_open(PERF_SECURITY_OPEN)')==1
assert core.count('security_perf_event_read(event)')==2 and core.count('security_perf_event_write(event)')==1
alloc=func(core,'perf_event_alloc');tail=alloc[alloc.index('\tif (!event->parent) {'):]
assert tail.index('security_perf_event_alloc(event)')<tail.index('account_event(event)')<tail.index('err_callchain:')
assert 'put_callchain_buffers();' in tail[tail.index('err_callchain:'):tail.index('err_per_task:')]
mm=func(core,'perf_mmap');mm=mm[:mm.index('\tvma_size = vma->vm_end - vma->vm_start;')]+'\treturn 99;\n}'
trace=(a.kernel/'kernel/trace/trace_event_perf.c').read_text();oldtrace=(a.before/'kernel/trace/trace_event_perf.c').read_text()
assert trace.count('security_perf_event_open(PERF_SECURITY_TRACEPOINT)')==2
sec=(a.kernel/'security/security.c').read_text();hooks=(a.kernel/(rel+'hooks.c')).read_text();lsm=(a.kernel/'include/linux/lsm_hooks.h').read_text()
macro=sec[sec.index('#define call_int_hook('):sec.index('\n\n',sec.index('#define call_int_hook('))]
register=lsm[lsm.index('#define LSM_HOOK_INIT('):lsm.index('\n\n',lsm.index('#define LSM_HOOK_INIT('))]
structlist=re.search(r'struct security_hook_list \{.*?\n};',lsm,re.S)[0]
obj=re.search(r'struct perf_event_security_struct \{.*?\n};',(a.kernel/(rel+'include/objsec.h')).read_text(),re.S)[0]
uapi=(a.kernel/'include/uapi/linux/perf_event.h').read_text();sample=re.search(r'enum perf_event_sample_format \{.*?\n};',uapi,re.S)[0]
parts=[r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
typedef uint32_t u32;typedef uint64_t u64;typedef long long fixture_loff_t;
#define loff_t fixture_loff_t
#define __user
#define GFP_KERNEL 1
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define ERR_PTR(n) ((void*)(intptr_t)(n))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define CAP_SYS_ADMIN 21
#define VM_SHARED 8
''',sample,obj]
for key in ['PERF_SECURITY_OPEN','PERF_SECURITY_CPU','PERF_SECURITY_KERNEL','PERF_SECURITY_TRACEPOINT','PERF_ATTACH_TASK']:parts.append(re.search(r'^#define '+key+r'\s+.*$',header,re.M)[0])
for i,(n,perms) in enumerate(new.items(),1):
 if n=='perf_event':
  parts.append(f'#define SECCLASS_PERF_EVENT {i}')
  for j,v in enumerate(perms):parts.append(f'#define PERF_EVENT__{v.upper()} (1U<<{j})')
parts.append(r'''
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD_INIT(n) {&(n),&(n)}
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,__typeof__(*p),m);&(p)->m!=(h);p=container_of((p)->m.next,__typeof__(*p),m))
static void list_add_tail_rcu(struct list_head *n,struct list_head *h){n->next=h;n->prev=h->prev;h->prev->next=n;h->prev=n;}
struct rcu_head {int unused;};struct pmu {int module;};struct perf_event_context {int unused;};
struct ring_buffer {int unused;};struct user_struct {int unused;};
struct perf_event_attr {u64 sample_type;int inherit,exclude_callchain_user;};
struct perf_event {void *security;struct perf_event *parent;struct perf_event_attr attr;int attach_state,cpu,pending,mmap_mutex,cgroup;struct ring_buffer *rb;struct pmu *pmu;struct perf_event_context *ctx;int *ns;struct rcu_head rcu_head;void (*destroy)(struct perf_event *);};
union security_list_options {
 int (*perf_event_open)(int);int (*perf_event_alloc)(struct perf_event *);
 int (*perf_event_read)(struct perf_event *);int (*perf_event_write)(struct perf_event *);
};
''',)
parts +=[structlist,'struct security_hook_heads {struct list_head perf_event_open,perf_event_alloc,perf_event_read,perf_event_write;};\nstatic struct security_hook_heads security_hook_heads={']
for n in ['open','alloc','read','write']:
 assert f'LSM_HOOK_INIT(perf_event_{n}, selinux_perf_event_{n})' in hooks
 parts.append(re.search(r'\t.perf_event_'+n+r' =\s*LIST_HEAD_INIT\(security_hook_heads.perf_event_'+n+r'\),',sec)[0])
parts+=['};',register,func(lsm,'security_add_hooks'),r'''
static u32 actor_sid=42,expected_target,expected_permission,denied;
static int integrity_error,policy_error=-EACCES;static unsigned avc_calls;
static int security_integrity_current(void){return integrity_error;}
static u32 current_sid(void){return actor_sid;}
static int avc_has_perm(u32 s,u32 t,unsigned short c,u32 p,void *ad){assert(s==actor_sid && t==expected_target && c==SECCLASS_PERF_EVENT && p==expected_permission && !ad);avc_calls++;return p&denied?policy_error:0;}
static struct perf_event *live_event;static void *live_label;
static unsigned label_allocs,label_frees,event_frees;static int malloc_fail,extra_alloc_error;
static void *kmalloc(size_t size,int flags){assert(size==sizeof(struct perf_event_security_struct) && flags==GFP_KERNEL && !live_label);if(malloc_fail)return NULL;live_label=malloc(size);assert(live_label);label_allocs++;return live_label;}
static void kfree(void *ptr){if(!ptr)return;if(ptr==live_label){free(ptr);live_label=NULL;label_frees++;}else{assert(ptr==live_event && !live_event->security);free(ptr);live_event=NULL;event_frees++;}}
''',macro]
for n in ['open','alloc','read','write']:parts.append(func(hooks,'selinux_perf_event_'+n))
parts.append('static struct security_hook_list selinux_hooks[]={'+','.join('LSM_HOOK_INIT(perf_event_'+n+',selinux_perf_event_'+n+')' for n in ['open','alloc','read','write'])+'};')
parts.append('static int extra_alloc(struct perf_event *e){(void)e;return extra_alloc_error;}\nstatic struct security_hook_list extra_hooks[]={LSM_HOOK_INIT(perf_event_alloc,extra_alloc)};')
for n in ['open','alloc','free','read','write']:parts.append(func(sec,'security_perf_event_'+n))
parts.append(r'''
static int namespace_ref,exclusive_ref,module_ref,callchain_ref,account_ref,context_ref,mutex_depth,callchain_error,destroy_calls,filter_frees;
static struct pmu fixture_pmu;static struct perf_event_context fixture_context;static struct ring_buffer fixture_rb;
static struct perf_event parent_marker;
static int get_callchain_buffers(void){if(callchain_error)return callchain_error;callchain_ref++;return 0;}
static void put_callchain_buffers(void){assert(callchain_ref==1);callchain_ref--;}
static void exclusive_event_destroy(struct perf_event *e){(void)e;assert(exclusive_ref==1);exclusive_ref--;}
static void module_put(int module){(void)module;assert(module_ref==1);module_ref--;}
static int is_cgroup_event(struct perf_event *e){return e->cgroup;}
static void perf_detach_cgroup(struct perf_event *e){assert(e->cgroup);e->cgroup=0;}
static void put_pid_ns(int *ns){assert(ns==&namespace_ref && namespace_ref==1);namespace_ref--;}
static void account_event(struct perf_event *e){(void)e;assert(!account_ref);account_ref++;}
static void unaccount_event(struct perf_event *e){(void)e;assert(account_ref==1);account_ref--;}
static void irq_work_sync(int *irq){(void)irq;}
static void mutex_lock(int *mutex){(void)mutex;assert(!mutex_depth);mutex_depth++;}
static void mutex_unlock(int *mutex){(void)mutex;assert(mutex_depth==1);mutex_depth--;}
static void ring_buffer_attach(struct perf_event *e,void *to){assert(e->rb && !to && !live_label && mutex_depth==1);e->rb=NULL;}
static void perf_event_free_bpf_prog(struct perf_event *e){(void)e;}
static void perf_event_free_filter(struct perf_event *e){(void)e;filter_frees++;}
static void put_ctx(struct perf_event_context *ctx){assert(ctx==&fixture_context && context_ref==1);context_ref--;}
static void call_rcu(struct rcu_head *head,void (*fn)(struct rcu_head *)){fn(head);}
static void destroy_event(struct perf_event *e){assert(e==live_event);destroy_calls++;}
''')
for n in ['free_event_rcu','__free_event','_free_event']:parts.append(func(core,n))
parts+=['static struct perf_event *fixture_alloc_tail(struct perf_event *event)\n{\nstruct pmu *pmu=event->pmu;long err=-EINVAL;\n'+tail,r'''
struct file {void *private_data;};struct vm_area_struct {unsigned vm_flags;struct file *vm_file;unsigned long vm_start,vm_end;};
static struct user_struct user;static struct user_struct *current_user(void){return &user;}
static unsigned read_backend,write_backend;static int io_error;
static struct perf_event_context *perf_event_ctx_lock(struct perf_event *e){(void)e;assert(!mutex_depth);mutex_depth=1;return &fixture_context;}
static void perf_event_ctx_unlock(struct perf_event *e,struct perf_event_context *ctx){(void)e;assert(ctx==&fixture_context && mutex_depth==1);mutex_depth=0;}
static int __perf_read(struct perf_event *e,char *buf,size_t count){(void)e;(void)buf;(void)count;assert(mutex_depth==1);read_backend++;return io_error?io_error:123;}
static int _perf_ioctl(struct perf_event *e,unsigned cmd,unsigned long arg){(void)e;(void)cmd;(void)arg;assert(mutex_depth==1);write_backend++;return io_error?io_error:321;}
''',func(core,'perf_read'),func(core,'perf_ioctl'),mm,r'''
static int sysctl_perf_event_paranoid,admin;
static int capable(int cap){assert(cap==CAP_SYS_ADMIN);return admin;}
#define TRACE_EVENT_FL_CAP_ANY 1
struct trace_event_call {int (*perf_perm)(struct trace_event_call *,struct perf_event *);int function;unsigned flags;};
static int ftrace_event_is_function(struct trace_event_call *t){return t->function;}
static int custom_error;
static int custom_perm(struct trace_event_call *t,struct perf_event *e){(void)t;(void)e;return custom_error;}
''']
for n in ['perf_paranoid_any','perf_paranoid_cpu','perf_paranoid_kernel','perf_paranoid_tracepoint_raw']:parts.append(func(header,n))
parts.append(func(oldtrace,'perf_trace_event_perm').replace('perf_trace_event_perm(', 'legacy_trace_permission(',1))
parts.append(func(trace,'perf_trace_event_perm'))
# CPU gate is a verbatim production fragment; scheduling after it is a fixture.
context=func(core,'find_get_context');cpu=context[context.index('\t\tif (perf_paranoid_cpu()'):context.index('\n\t\t/*\n\t\t * We could be clever')]
parts.append('static void *fixture_cpu_gate(void){int err;\n'+cpu+'\nreturn NULL;\n}')
parts.append(r'''
static void reset(void){assert(!live_label && !live_event);label_allocs=label_frees=event_frees=0;malloc_fail=extra_alloc_error=integrity_error=0;denied=0;avc_calls=read_backend=write_backend=0;io_error=0;namespace_ref=exclusive_ref=module_ref=callchain_ref=account_ref=context_ref=mutex_depth=0;callchain_error=destroy_calls=filter_frees=0;}
int main(void){
 assert(security_hook_heads.perf_event_alloc.next==&security_hook_heads.perf_event_alloc);
 security_add_hooks(selinux_hooks,4);security_add_hooks(extra_hooks,1);
 unsigned long ops=0,lifetimes=0,io=0,traces=0,cpu=0;
 const u32 sids[]={1,42,84};const int modes[]={-1,0,1,2,3,4,999};const u32 openbits[]={PERF_EVENT__OPEN,PERF_EVENT__CPU,PERF_EVENT__KERNEL,PERF_EVENT__TRACEPOINT};
 for(unsigned s=0;s<3;s++)for(unsigned d=0;d<64;d++)for(unsigned mode=0;mode<7;mode++)for(unsigned error=0;error<2;error++)for(unsigned integrity=0;integrity<2;integrity++){
  reset();actor_sid=sids[s];expected_target=actor_sid;denied=d;policy_error=error?-ENOMEM:-EACCES;integrity_error=integrity?-EFAULT:0;
  int valid=modes[mode]>=0&&modes[mode]<4;expected_permission=valid?openbits[modes[mode]]:0;
  int expected=integrity_error?integrity_error:!valid?-EINVAL:denied&expected_permission?policy_error:0;
  int rc=security_perf_event_open(modes[mode]);assert(rc==expected && avc_calls==(unsigned)(!integrity&&valid));ops++;
 }
 for(unsigned s=0;s<3;s++)for(unsigned t=0;t<3;t++)for(unsigned d=0;d<64;d++)for(unsigned missing=0;missing<2;missing++)for(unsigned integrity=0;integrity<2;integrity++){
  reset();actor_sid=sids[s];expected_target=sids[t];denied=d;integrity_error=integrity?-EFAULT:0;policy_error=-EACCES;
  struct perf_event_security_struct label={sids[t]};struct perf_event event={0};event.security=missing?NULL:&label;
  for(unsigned write=0;write<2;write++){expected_permission=write?PERF_EVENT__WRITE:PERF_EVENT__READ;avc_calls=0;int expected=integrity_error?integrity_error:missing?-EACCES:denied&expected_permission?policy_error:0;
   int rc=write?security_perf_event_write(&event):security_perf_event_read(&event);assert(rc==expected && avc_calls==(unsigned)(!integrity&&!missing));ops++;}
 }
 for(unsigned parent=0;parent<2;parent++)for(unsigned chain=0;chain<2;chain++)for(unsigned getfail=0;getfail<2;getfail++)for(unsigned mallocfail=0;mallocfail<2;mallocfail++)for(unsigned integrity=0;integrity<2;integrity++)for(unsigned extra=0;extra<2;extra++)for(unsigned installed=0;installed<2;installed++){
  reset();actor_sid=42;callchain_error=getfail?-ENOSPC:0;malloc_fail=mallocfail;integrity_error=integrity?-EFAULT:0;extra_alloc_error=extra?-EIO:0;
  live_event=calloc(1,sizeof(*live_event));assert(live_event);live_event->parent=parent?&parent_marker:NULL;live_event->attr.sample_type=chain?PERF_SAMPLE_CALLCHAIN:0;live_event->pmu=&fixture_pmu;live_event->ns=&namespace_ref;live_event->destroy=destroy_event;live_event->cgroup=1;namespace_ref=exclusive_ref=module_ref=1;
  int expected=!parent&&chain&&getfail?-ENOSPC:integrity?-EFAULT:mallocfail?-ENOMEM:extra?-EIO:0;
  struct perf_event *result=fixture_alloc_tail(live_event);
  if(expected){assert(IS_ERR(result) && PTR_ERR(result)==expected && !live_event && !live_label && event_frees==1 && !account_ref);}
  else {assert(result==live_event && result->security==live_label && ((struct perf_event_security_struct*)result->security)->sid==42 && account_ref==1);
   result->rb=&fixture_rb;if(installed){result->ctx=&fixture_context;context_ref=1;}
   integrity_error=-EFAULT;_free_event(result);assert(!live_event && !live_label && event_frees==1 && !account_ref && !context_ref && filter_frees==1);}
  assert(!namespace_ref && !exclusive_ref && !module_ref && !callchain_ref && !mutex_depth && label_allocs==label_frees && destroy_calls==1);lifetimes++;
 }
 for(unsigned d=0;d<64;d++)for(unsigned missing=0;missing<2;missing++)for(unsigned inherit=0;inherit<2;inherit++)for(unsigned shared=0;shared<2;shared++)for(unsigned cpu_bound=0;cpu_bound<2;cpu_bound++)for(unsigned backend_error=0;backend_error<2;backend_error++){
  reset();actor_sid=42;expected_target=84;denied=d;policy_error=-EACCES;io_error=backend_error?-ENOMEM:0;struct perf_event_security_struct label={84};struct perf_event event={0};event.security=missing?NULL:&label;event.cpu=cpu_bound?0:-1;event.attr.inherit=inherit;struct file file={&event};struct vm_area_struct vma={shared?VM_SHARED:0,&file,0,4096};
  expected_permission=PERF_EVENT__READ;int denied_read=missing||(denied&PERF_EVENT__READ);int rc=perf_read(&file,NULL,8,NULL);assert(rc==(denied_read?-EACCES:io_error?io_error:123) && read_backend==(unsigned)!denied_read && !mutex_depth);
  expected_permission=PERF_EVENT__WRITE;int denied_write=missing||(denied&PERF_EVENT__WRITE);rc=perf_ioctl(&file,0,0);assert(rc==(denied_write?-EACCES:io_error?io_error:321) && write_backend==(unsigned)!denied_write && !mutex_depth);
  expected_permission=PERF_EVENT__READ;rc=perf_mmap(&file,&vma);int invalid=(!cpu_bound&&inherit)||!shared;assert(rc==(invalid?-EINVAL:denied_read?-EACCES:99));io+=3;
 }
 for(unsigned parent=0;parent<2;parent++)for(unsigned function=0;function<2;function++)for(unsigned raw=0;raw<2;raw++)for(unsigned stack=0;stack<2;stack++)for(unsigned exclude=0;exclude<2;exclude++)for(unsigned task=0;task<2;task++)for(unsigned any=0;any<2;any++)for(int paranoid=-2;paranoid<4;paranoid++)for(unsigned cap=0;cap<2;cap++)for(unsigned custom=0;custom<2;custom++){
  reset();actor_sid=42;expected_target=42;expected_permission=PERF_EVENT__TRACEPOINT;sysctl_perf_event_paranoid=paranoid;admin=cap;custom_error=custom?-EIO:0;
  struct trace_event_call t={custom_perm,function,any?TRACE_EVENT_FL_CAP_ANY:0};struct perf_event e={0};e.parent=parent?&parent_marker:NULL;e.attach_state=task?PERF_ATTACH_TASK:0;e.attr.sample_type=(raw?PERF_SAMPLE_RAW:0)|(stack?PERF_SAMPLE_STACK_USER:0);e.attr.exclude_callchain_user=exclude;
  int reference=legacy_trace_permission(&t,&e);int rc=perf_trace_event_perm(&t,&e);assert(rc==reference);unsigned gates=avc_calls;avc_calls=0;denied=PERF_EVENT__TRACEPOINT;policy_error=-EACCES;rc=perf_trace_event_perm(&t,&e);assert(rc==(gates?-EACCES:reference));assert(avc_calls==(unsigned)(gates!=0));traces+=2;
 }
 for(int paranoia=-2;paranoia<4;paranoia++)for(unsigned cap=0;cap<2;cap++)for(unsigned deny=0;deny<2;deny++){
  reset();actor_sid=42;expected_target=42;expected_permission=PERF_EVENT__CPU;sysctl_perf_event_paranoid=paranoia;admin=cap;denied=deny?PERF_EVENT__CPU:0;
  assert(perf_paranoid_any()==(paranoia>2) && perf_paranoid_kernel()==(paranoia>1));
  void *result=fixture_cpu_gate();int expected=paranoia>0&&!cap?-EACCES:deny?-EACCES:0;
  assert(expected?(IS_ERR(result)&&PTR_ERR(result)==expected):result==NULL);assert(avc_calls==(unsigned)(!(paranoia>0&&!cap)));cpu++;
 }
 printf("PASS: %lu LSM/owner-label, %lu allocation/free-unwind, %lu read/ioctl/mmap-fragment, %lu old-vs-new trace, %lu CPU-gate scenarios\n",ops,lifetimes,io,traces,cpu);
 return 0;
}
''')
with tempfile.TemporaryDirectory(prefix='perf-lsm-') as d:
 t=Path(d);(t/'test.c').write_text('\n'.join(parts));command=['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-variable','-Wno-unused-label','-Wno-unused-but-set-variable','-Wno-unused-parameter','-Wno-sign-compare','-fsanitize=address,undefined',str(t/'test.c'),'-o',str(t/'test')]
 subprocess.run(command,check=True);result=subprocess.run([str(t/'test')],check=True,text=True,capture_output=True);print(result.stdout,end='')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
paths=['kernel/events/core.c','kernel/trace/trace_event_perf.c','include/linux/perf_event.h','include/linux/security.h','include/linux/lsm_hooks.h','security/security.c',rel+'hooks.c',rel+'include/objsec.h',rel+'include/classmap.h','include/uapi/linux/perf_event.h'];files=[a.kernel/x for x in paths]+[a.before/x for x in ['kernel/events/core.c','kernel/trace/trace_event_perf.c','include/linux/perf_event.h',rel+'include/classmap.h']]
a.report.write_text(json.dumps({'passed':True,'scope':__doc__,'result':result.stdout.strip(),'existing_class_and_permission_ids_unchanged':True,'old_paranoia_helpers_and_compat_ioctl_unchanged':True,'extractor_sha256':sha(Path(extractor.__file__)),'classmap_reader_sha256':sha(Path(surface.__file__)),'runner_sha256':sha(Path(__file__)),'inputs_sha256':{str(f):sha(f) for f in files},'hardware_tested':False,'real_perf_scheduling_or_full_open_context_executed':False},indent=2)+'\n')
