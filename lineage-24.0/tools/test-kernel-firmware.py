#!/usr/bin/env python3
"""Actual firmware hook/LSM and loader bodies with sequential fixture backends.

No real filesystem, firmware device, IMA, concurrency or hardware is executed.
"""
import argparse,hashlib,importlib.util,json,re,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for k in ['kernel','before','report']:p.add_argument('--'+k,type=Path,required=True)
a=p.parse_args();assert not a.report.exists()
def mod(n,f):
 s=importlib.util.spec_from_file_location(n,Path(__file__).with_name(f));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
fn=mod('extract','test-netlink-xperm24.py').function;table=mod('surface','audit-kernel-policy-surface.py').table
rel='security/selinux/';old=table(a.before/(rel+'include/classmap.h'),'clang');new=table(a.kernel/(rel+'include/classmap.h'),'clang');assert list(old)==list(new)
for k in old:assert new[k]==old[k]+(['firmware_load'] if k=='system' else [])
hooks=(a.kernel/(rel+'hooks.c')).read_text();core=(a.kernel/'security/security.c').read_text();lsm=(a.kernel/'include/linux/lsm_hooks.h').read_text();loader=(a.kernel/'drivers/base/firmware_class.c').read_text()
assert fn(hooks,'selinux_kernel_module_from_file')==fn((a.before/(rel+'hooks.c')).read_text(),'selinux_kernel_module_from_file')
assert 'LSM_HOOK_INIT(kernel_fw_from_file, selinux_kernel_fw_from_file)' in hooks
assert fn(core,'security_kernel_fw_from_file')==fn((a.before/'security/security.c').read_text(),'security_kernel_fw_from_file')
macro=core[core.index('#define call_int_hook('):core.index('\n\n',core.index('#define call_int_hook('))]
init=re.search(r'\t.kernel_fw_from_file =\s*LIST_HEAD_INIT\(security_hook_heads.kernel_fw_from_file\),',core)[0]
register=lsm[lsm.index('#define LSM_HOOK_INIT('):lsm.index('\n\n',lsm.index('#define LSM_HOOK_INIT('))]
structlist=re.search(r'struct security_hook_list \{.*?\n};',lsm,re.S)[0]
parts=[r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
typedef uint32_t u32;
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define unlikely(x) (x)
#define LSM_AUDIT_DATA_PATH 1
#define S_ISREG(m) ((m)==1)
struct inode_security_struct {u32 sid;};
struct inode {struct inode_security_struct *i_security;int i_mode,size;};
struct file_security_struct {u32 sid;};
struct path {void *dentry,*mnt;};
struct file {struct path f_path;struct inode *f_inode;struct file_security_struct *f_security;};
#define file_inode(f) ((f)->f_inode)
static u32 actor_sid;
static u32 current_sid(void) {return actor_sid;}
struct common_audit_data {int type;union {struct path path;} u;};
static int fd_error,system_error,integrity_error,ima_error;
static unsigned fd_checks,system_checks,ima_checks;
static struct inode_security_struct isec={83};
static struct inode inode={&isec,1,16};
static struct file_security_struct fsec={42};
static struct file file={{&inode,&isec},&inode,&fsec};
static int expected_file;
''']
for k,perms in new.items():
 parts.append(f'#define SECCLASS_{k.upper()} {list(new).index(k)+1}')
 for j,v in enumerate(perms):parts.append(f'#define {k.upper()}__{v.upper()} (1U<<{j})')
parts.append(r'''
static int avc_has_perm(u32 s,u32 t,unsigned c,u32 perm,struct common_audit_data *ad) {
 assert(s==actor_sid);
 if(expected_file)assert(ad && ad->type==LSM_AUDIT_DATA_PATH && ad->u.path.dentry==&inode && ad->u.path.mnt==&isec);
 else assert(!ad);
 if(c==SECCLASS_FD){assert(expected_file && s!=fsec.sid && t==fsec.sid && perm==FD__USE);fd_checks++;return fd_error;}
 assert(c==SECCLASS_SYSTEM && perm==SYSTEM__FIRMWARE_LOAD && t==(expected_file?isec.sid:s));system_checks++;return system_error;
}
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD_INIT(n) {&(n),&(n)}
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,__typeof__(*p),m);&(p)->m!=(h);p=container_of((p)->m.next,__typeof__(*p),m))
static void list_add_tail_rcu(struct list_head *n,struct list_head *h) {n->next=h;n->prev=h->prev;h->prev->next=n;h->prev=n;}
union security_list_options {int (*kernel_fw_from_file)(struct file *,char *,size_t);};
''')
parts +=[structlist,'struct security_hook_heads {struct list_head kernel_fw_from_file;};\nstatic struct security_hook_heads security_hook_heads={',init,'};',register,fn(lsm,'security_add_hooks'),'static int security_integrity_current(void) {return integrity_error;}',macro,fn(hooks,'selinux_kernel_fw_from_file'),r'''
static struct security_hook_list fixture_hooks[]={LSM_HOOK_INIT(kernel_fw_from_file,selinux_kernel_fw_from_file)};
static int ima_fw_from_file(struct file *f,char *buf,size_t size){assert((f!=NULL)==expected_file && buf && size==16);ima_checks++;return ima_error;}
''',fn(core,'security_kernel_fw_from_file'),r'''
struct firmware_buf {char *data;size_t size;unsigned long status;int nr_pages,page_array_size;void **pages;struct list_head pending_list;int completion;};
static int alloc_error,read_result,map_error,live_allocations,map_calls,completed,aborted,locked;
static int i_size_read(struct inode *i){return i->size;}
static void *vmalloc(size_t size){if(alloc_error)return NULL;live_allocations++;return malloc(size);}
static void vfree(void *p){assert(live_allocations==1);live_allocations--;free(p);}
static int kernel_read(struct file *f,int off,char *buf,int size){assert(f==&file && off==0 && buf && size==16);memset(buf,0,size);return read_result;}
''',fn(loader,'fw_read_file_contents'),r'''
#define FW_STATUS_DONE 0
#define FW_STATUS_LOADING 1
#define FW_STATUS_ABORT 2
struct firmware_priv {struct firmware_buf *buf;};
struct device {struct firmware_priv *priv;};struct device_attribute {int unused;};
static int fw_lock;
static struct firmware_priv *to_firmware_priv(struct device *d){return d->priv;}
static int test_bit(int bit,unsigned long *p){return (*p>>bit)&1;}
static void set_bit(int bit,unsigned long *p){*p|=1UL<<bit;}
static void clear_bit(int bit,unsigned long *p){*p&=~(1UL<<bit);}
static long simple_strtol(const char *s,char **end,int base){return strtol(s,end,base);}
static void mutex_lock(int *l){assert(l==&fw_lock && !locked);locked=1;}
static void mutex_unlock(int *l){assert(l==&fw_lock && locked);locked=0;}
static void __free_page(void *p){free(p);}
#define kfree(p) free(p)
#define dev_err(...) ((void)0)
static int fw_map_pages_buf(struct firmware_buf *b){assert(b->data && b->size==16);map_calls++;return map_error;}
static void list_del_init(struct list_head *h){h->next=h;h->prev=h;}
static void complete_all(int *c){assert(locked);(*c)++;completed++;}
static void fw_load_abort(struct firmware_priv *p){assert(p->buf);aborted++;}
''',fn(loader,'firmware_loading_store'),r'''
static void reset(void){actor_sid=42;fsec.sid=42;inode.i_mode=1;inode.size=16;fd_error=system_error=integrity_error=ima_error=0;fd_checks=system_checks=ima_checks=0;expected_file=0;alloc_error=map_error=0;read_result=16;live_allocations=map_calls=completed=aborted=locked=0;}
int main(void){
 assert(security_hook_heads.kernel_fw_from_file.next==&security_hook_heads.kernel_fw_from_file);
 security_add_hooks(fixture_hooks,ARRAY_SIZE(fixture_hooks));
 int errors[]={0,-EACCES,-EPERM,-ENOMEM};char bytes[16]={0};unsigned hooks=0,direct=0,fallback=0;
 for(int f=0;f<2;f++)for(int same=0;same<2;same++)for(int fe=0;fe<4;fe++)for(int se=0;se<4;se++)for(int ie=0;ie<4;ie++)for(int ke=0;ke<4;ke++){
  reset();expected_file=f;fsec.sid=same?actor_sid:84;fd_error=errors[fe];system_error=errors[se];ima_error=errors[ie];integrity_error=errors[ke];
  int fd=f&&!same;int expected=integrity_error?integrity_error:fd&&fd_error?fd_error:system_error?system_error:ima_error;
  assert(security_kernel_fw_from_file(f?&file:NULL,bytes,16)==expected);
  assert(fd_checks==(unsigned)(!integrity_error&&fd));assert(system_checks==(unsigned)(!integrity_error&&(!fd||!fd_error)));
  assert(ima_checks==(unsigned)(!integrity_error&&(!fd||!fd_error)&&!system_error));hooks++;
 }
 for(int mode=0;mode<2;mode++)for(int size=0;size<3;size++)for(int alloc=0;alloc<2;alloc++)for(int read=0;read<4;read++)for(int same=0;same<2;same++)for(int fe=0;fe<4;fe++)for(int se=0;se<4;se++)for(int ie=0;ie<4;ie++){
  reset();expected_file=1;inode.i_mode=mode;inode.size=size==0?-1:size==1?0:16;alloc_error=alloc;int reads[]={-EIO,0,8,16};read_result=reads[read];fsec.sid=same?42:84;fd_error=errors[fe];system_error=errors[se];ima_error=errors[ie];
  struct firmware_buf b={0};int expected=!mode||size<2?-EINVAL:alloc?-ENOMEM:read<3?(read_result>0?-EIO:read_result):!same&&fd_error?fd_error:system_error?system_error:ima_error;
  int rc=fw_read_file_contents(&file,&b);assert(rc==expected);
  int published=mode&&size==2&&!alloc&&read==3&&(same||!fd_error)&&!system_error&&!ima_error;
  assert((b.data!=NULL)==published);assert(live_allocations==published);if(published){assert(b.size==16);vfree(b.data);}assert(!live_allocations);direct++;
 }
 for(int value=-1;value<3;value++)for(int present=0;present<2;present++)for(int loading=0;loading<2;loading++)for(int done=0;done<2;done++)for(int map=0;map<2;map++)for(int se=0;se<4;se++)for(int ie=0;ie<4;ie++){
  reset();system_error=errors[se];ima_error=errors[ie];map_error=map?-ENOMEM:0;
  struct firmware_buf b={.data=bytes,.size=16,.status=(loading?2:0)|(done?1:0)};struct firmware_priv priv={present?&b:NULL};struct device dev={&priv};char text[4];snprintf(text,sizeof(text),"%d",value);
  int reached=present&&value==0&&loading;int error=map_error?map_error:system_error?system_error:ima_error;
  ssize_t rc=firmware_loading_store(&dev,NULL,text,2);assert(rc==(reached&&error?error:2));assert(!locked);
  assert(map_calls==reached && completed==reached);assert(system_checks==(unsigned)(reached&&!map_error));assert(ima_checks==(unsigned)(reached&&!map_error&&!system_error));
  if(reached){assert(test_bit(FW_STATUS_DONE,&b.status)&&!test_bit(FW_STATUS_LOADING,&b.status));assert(test_bit(FW_STATUS_ABORT,&b.status)==!!error);}fallback++;
 }
 printf("PASS: %u firmware LSM/FD/IMA, %u full direct-loader, %u full user-helper completion scenarios\n",hooks,direct,fallback);
}
''']
with tempfile.TemporaryDirectory(prefix='firmware-') as d:
 t=Path(d);(t/'test.c').write_text('\n'.join(parts));subprocess.run(['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-sign-compare','-fsanitize=address,undefined',str(t/'test.c'),'-o',str(t/'test')],check=True);result=subprocess.run([str(t/'test')],text=True,capture_output=True,check=True);print(result.stdout,end='')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
paths=['drivers/base/firmware_class.c','security/security.c','include/linux/lsm_hooks.h',rel+'hooks.c',rel+'include/classmap.h']
a.report.write_text(json.dumps({'passed':True,'scope':__doc__,'result':result.stdout.strip(),'old_class_and_permission_ids_unchanged':True,'module_hook_and_common_IMA_wrapper_unchanged':True,'runner_sha256':sha(Path(__file__)),'extractor_sha256':sha(Path(__file__).with_name('test-netlink-xperm24.py')),'inputs_sha256':{str(a.kernel/n):sha(a.kernel/n) for n in paths},'hardware_tested':False},indent=2)+'\n')
