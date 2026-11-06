#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise actual ARM64 register-stack collector bodies in bounded host fixtures.

The unwinder/task stack and module lookup are mocked; no live interrupt proof.
"""
import argparse,hashlib,importlib.util,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['source','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir()
spec=importlib.util.spec_from_file_location('extract',Path(__file__).with_name('test-netlink-xperm24.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
src=a.source/'arch/arm64/kernel/stacktrace.c';gator=a.source/'drivers/gator/gator_backtrace.c';text=src.read_text()
bodies=m.function(text,'save_trace')+'\n'+m.function(text,'save_stack_trace_regs')
report=m.function(gator.read_text().split('/* -------------------------- KERNEL UNWINDING USING save_stack_trace_regs')[1],'report_trace')
header=r'''
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
struct pt_regs {unsigned long regs[31],sp,pc;};
struct stack_trace {unsigned nr_entries,max_entries;unsigned long *entries;int skip;};
struct stackframe {unsigned long fp,sp,pc;int graph;};
struct task_struct {int curr_ret_stack;};
static struct task_struct task={7},*current=&task;
struct stack_trace_data {struct stack_trace *trace;unsigned no_sched_functions,skip;};
static int acquired,released,available=1,walks;
static unsigned long expectfp,expectsp,expectpc;
static bool in_sched_functions(unsigned long a){return a==0;}
static int try_get_task_stack(struct task_struct *t){assert(t==current);acquired++;return available;}
static void put_task_stack(struct task_struct *t){assert(t==current);released++;}
static void walk_stackframe(struct task_struct *t,struct stackframe *f,int(*fn)(struct stackframe*,void*),void *d){
 assert(t==current&&f->fp==expectfp&&f->sp==expectsp&&f->pc==expectpc);walks++;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
 assert(f->graph==7);
#endif
 for(unsigned i=0;i<4;i++){f->pc=expectpc+i*4;if(fn(f,d))break;}
}
#define NO_COOKIE 0
static unsigned emitted,lookups;
struct module {char *name;struct {unsigned long base;}core_layout;};
static struct module * __module_address(unsigned long a){assert(a!=ULONG_MAX);lookups++;return NULL;}
static unsigned get_cookie(unsigned c,struct task_struct *t,char *n,bool x){(void)c;(void)t;(void)n;(void)x;return 1;}
static void marshal_backtrace(unsigned long a,unsigned c,int x){assert(a!=ULONG_MAX);(void)c;(void)x;emitted++;}
#define LINUX_VERSION_CODE 0x040900
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
'''
main=r'''
int main(void){
 struct pt_regs regs={.regs={[29]=0x1200},.sp=0x1000,.pc=0x8000};
 expectfp=regs.regs[29];expectsp=regs.sp;expectpc=regs.pc;
 unsigned cases=0;
 for(unsigned max=0;max<=6;max++)for(unsigned skip=0;skip<=5;skip++)for(unsigned initial=0;initial<=max;initial++){
  unsigned long buffer[9];for(unsigned i=0;i<9;i++)buffer[i]=0xdead;
  struct stack_trace trace={initial,max,buffer+1,skip};int oldwalks=walks;
  save_stack_trace_regs(&regs,&trace);assert(trace.nr_entries<=max&&buffer[0]==0xdead&&buffer[max+1]==0xdead);
  unsigned n=4>skip?4-skip:0,remaining=max-initial;if(n>remaining)n=remaining;
  assert(trace.nr_entries==initial+n+((initial<max&&n<remaining)?1:0));
  for(unsigned i=0;i<n;i++)assert(trace.entries[initial+i]==regs.pc+(skip+i)*4);
  if(initial<max&&n<remaining)assert(trace.entries[initial+n]==ULONG_MAX);
  assert(walks==oldwalks+(initial<max));cases++;
 }
 unsigned long b[5]={0};struct stack_trace t={0,4,b,0};int w=walks;
 save_stack_trace_regs(NULL,&t);assert(!t.nr_entries&&walks==w);
 available=0;save_stack_trace_regs(&regs,&t);assert(!t.nr_entries&&walks==w);available=1;
 assert(acquired==released+1);
 unsigned long entries[]={0x8000,ULONG_MAX,0x9999};t.entries=entries;t.nr_entries=3;
 report_trace(0,&t);assert(emitted==1&&lookups==1);
 return cases==168?0:1;
}
'''
# 6 * sum(max+1 for max in 0..6) = 168 bounded combinations per build.
program=header+bodies+'\n'+report+main;(a.output/'fixture.c').write_text(program)
results=[]
for graph in [False,True]:
 binary=a.output/('graph' if graph else 'plain');cmd=['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=address,undefined','-DMODULE',*(['-DCONFIG_FUNCTION_GRAPH_TRACER'] if graph else []),str(a.output/'fixture.c'),'-o',str(binary)]
 r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr
 r=subprocess.run([str(binary)],capture_output=True,text=True,env=dict(os.environ,UBSAN_OPTIONS='halt_on_error=1'));(a.output/(binary.name+'.log')).write_text(r.stdout+r.stderr);assert r.returncode==0 and not r.stderr,r.stdout+r.stderr
 results.append({'function_graph':graph,'bounded_cases':168,'null_registers_and_unavailable_stack':True,'module_sentinel_rejected':True,'command':cmd})
(a.output/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'results':results,'inputs_sha256':{str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in [src,gator,Path(__file__)]},'hardware_tested':False},indent=2)+'\n');print('PASS: actual register collector and Gator sentinel bodies; 336 bounded cases plus null/stack controls')
