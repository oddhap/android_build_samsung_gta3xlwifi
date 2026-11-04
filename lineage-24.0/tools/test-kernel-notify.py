#!/usr/bin/env python3
"""Actual notify SELinux/LSM bodies, full inotify syscall and dnotify prefix.

Credential, list/dispatch mechanics, inode/path, user lookup, fd/reference and
mark backends are sequential fixtures. Dnotify stops at its first allocation;
mark lifecycle, real watches, concurrency and hardware are not executed.
"""
import argparse,hashlib,importlib.util,json,re,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ['kernel','before','inotify-header','report']:p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();assert not a.report.exists()
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
func=module('extract','test-netlink-xperm24.py').function;table=module('surface','audit-kernel-policy-surface.py').table
rel='security/selinux/';old=table(a.before/(rel+'include/classmap.h'),'clang');new=table(a.kernel/(rel+'include/classmap.h'),'clang');assert list(old)==list(new)
changed=[]
for name,perms in new.items():
 assert [v for v in perms if v not in ['watch','watch_reads']]==old[name]
 if perms!=old[name]:changed.append(name)
for name in ['file','dir','lnk_file','chr_file','blk_file','sock_file','fifo_file']:
 assert new[name].index('watch')==new['file'].index('watch');assert new[name].index('watch_reads')==new['file'].index('watch_reads')
# Preserve original DAC/path reference handling and argument conversion.
inopath='fs/notify/inotify/inotify_user.c';dnpath='fs/notify/dnotify/dnotify.c'
ino=(a.kernel/inopath).read_text();dno=(a.kernel/dnpath).read_text()
for path,fn in [(inopath,'inotify_find_inode'),(inopath,'inotify_arg_to_mask'),(dnpath,'convert_arg')]:assert func((a.kernel/path).read_text(),fn)==func((a.before/path).read_text(),fn)
head=(a.kernel/'include/linux/security.h').read_text();lsm=(a.kernel/'include/linux/lsm_hooks.h').read_text();core=(a.kernel/'security/security.c').read_text();hooks=(a.kernel/(rel+'hooks.c')).read_text()
assert 'struct list_head path_notify;' in lsm and 'int (*path_notify)(const struct path *path, u64 mask, unsigned int obj_type);' in lsm
assert 'LSM_HOOK_INIT(path_notify, selinux_path_notify)' in hooks
macro=core[core.index('#define call_int_hook('):core.index('\n\n',core.index('#define call_int_hook('))]
init=re.search(r'\t.path_notify =\s*LIST_HEAD_INIT\(security_hook_heads.path_notify\),',core)[0]
register=lsm[lsm.index('#define LSM_HOOK_INIT('):lsm.index('\n\n',lsm.index('#define LSM_HOOK_INIT('))]
structlist=re.search(r'struct security_hook_list \{.*?\n};',lsm,re.S)[0]
def defines(s):
 # Retain complete real multiline preprocessor definitions, not host UAPI.
 lines=s.splitlines();out=[];i=0
 while i<len(lines):
  line=lines[i]
  if re.match(r'^#define\s+(?:FS_|ALL_FSNOTIFY|IN_|ALL_INOTIFY|DN_)\w*\b',line):
   out.append(line)
   while out[-1].rstrip().endswith('\\'):i+=1;out.append(lines[i])
  i+=1
 return '\n'.join(out)
backend=(a.kernel/'include/linux/fsnotify_backend.h').read_text();obj=re.search(r'enum fsnotify_obj_type \{.*?\n};',backend,re.S)[0]
parts=[r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;typedef uint64_t u64;typedef uint32_t __u32;
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define unlikely(x) (x)
#define __user
#define LSM_AUDIT_DATA_PATH 1
#define S_IFDIR 0040000
#define S_IFREG 0100000
#define S_ISDIR(m) (((m)&0170000)==S_IFDIR)
#define MAY_READ 4
#define AT_FDCWD -100
#define LOOKUP_FOLLOW 1
#define LOOKUP_DIRECTORY 2
''',defines(backend),defines((a.kernel/'include/uapi/linux/inotify.h').read_text()),defines((a.kernel/'include/uapi/linux/fcntl.h').read_text()),defines(a.inotify_header.read_text()),obj]
for i,(name,perms) in enumerate(new.items(),1):
 parts.append(f'#define SECCLASS_{name.upper()} {i}')
 for j,v in enumerate(perms):parts.append(f'#define {name.upper()}__{v.upper()} (1U<<{j})')
parts.append(r'''
struct cred {u32 sid;};static struct cred actorcred={42};
static const struct cred *current_cred(void) {return &actorcred;}
static u32 cred_sid(const struct cred *cred) {assert(cred==&actorcred);return cred->sid;}
#define validate_creds(c) assert((c)==&actorcred)
struct inode_security_struct {u32 sid;unsigned short sclass;};
struct inode {struct inode_security_struct *i_security;unsigned i_mode;int private;};
struct path;
struct dentry_operations {void (*d_canonical_path)(const struct path *,struct path *);};
struct dentry {struct inode *d_inode;const struct dentry_operations *d_op;};
struct path {struct dentry *dentry;void *mnt;};
static struct inode_security_struct uppersec={83,SECCLASS_FILE},lowersec={84,SECCLASS_FILE};
static struct inode upper={&uppersec,S_IFREG,0},lower={&lowersec,S_IFREG,0};
static struct dentry upperentry={&upper,NULL},lowerentry={&lower,NULL};
static struct inode *d_backing_inode(const struct dentry *dentry) {return dentry->d_inode;}
#define IS_PRIVATE(i) ((i)->private)
struct common_audit_data {int type;union {struct path path;} u;};
static int integrity_error,permission_error;static unsigned avc_calls;static u32 expected_perms;
static struct inode *expected_inode;
static int avc_has_perm(u32 s,u32 t,unsigned short c,u32 perms,struct common_audit_data *ad) {
 assert(s==42 && t==expected_inode->i_security->sid && c==expected_inode->i_security->sclass);
 assert(perms==expected_perms && ad->type==LSM_AUDIT_DATA_PATH && ad->u.path.dentry->d_inode==expected_inode);
 avc_calls++;return permission_error;
}
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD_INIT(n) {&(n),&(n)}
#define container_of(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,__typeof__(*p),m);&(p)->m!=(h);p=container_of((p)->m.next,__typeof__(*p),m))
static void list_add_tail_rcu(struct list_head *node,struct list_head *head) {node->next=head;node->prev=head->prev;head->prev->next=node;head->prev=node;}
union security_list_options {int (*path_notify)(const struct path *,u64,unsigned);};
''')
parts +=[structlist,'struct security_hook_heads {struct list_head path_notify;};\nstatic struct security_hook_heads security_hook_heads={',init,'};',register,func(lsm,'security_add_hooks'),'static int security_integrity_current(void) {return integrity_error;}',macro]
for fn in ['inode_has_perm','path_has_perm','selinux_path_notify']:parts.append(func(hooks,fn))
parts+=['static struct security_hook_list selinux_hooks[]={LSM_HOOK_INIT(path_notify,selinux_path_notify)};',func(core,'security_path_notify'),r'''
struct fsnotify_group {int unused;};static struct fsnotify_group group;
struct file {const void *f_op;void *private_data;struct path f_path;struct inode *f_inode;};
struct fd {struct file *file;};static int inotify_fops,otherops;
static struct file fdfile={&inotify_fops,&group,{&upperentry,NULL},&upper};
static unsigned fdgets,fdputs,marks,flushes;static int upperrefs,lowerrefs,path_error,dac_error,mark_error,badfd;
static unsigned observed_lookup_flags;
static struct fd fdget(int fd) {assert(fd==7);fdgets++;return (struct fd){badfd?NULL:&fdfile};}
static void fdput(struct fd f) {assert(f.file==&fdfile);fdputs++;}
static int user_path_at(int dfd,const char *name,unsigned flags,struct path *path) {
 assert(dfd==AT_FDCWD && name);observed_lookup_flags=flags;if(path_error)return path_error;
 path->dentry=&upperentry;path->mnt=NULL;upperrefs++;return 0;
}
static int inode_permission2(void *mnt,struct inode *inode,int perms) {assert(mnt==NULL && inode==&upper && perms==MAY_READ);return dac_error;}
static void path_put(const struct path *path) {
 if(path->dentry==&upperentry){assert(upperrefs==1);upperrefs--;}
 else {assert(path->dentry==&lowerentry && lowerrefs==1);lowerrefs--;}
}
static void canonical(const struct path *old,struct path *new) {assert(old->dentry==&upperentry && upperrefs==1);new->dentry=&lowerentry;new->mnt=NULL;lowerrefs++;}
static const struct dentry_operations stacked_ops={canonical};
static int inotify_update_watch(struct fsnotify_group *g,struct inode *inode,u32 mask) {assert(g==&group && inode==expected_inode && mask);marks++;return mark_error?mark_error:99;}
''']
for fn in ['inotify_find_inode','inotify_arg_to_mask']:parts.append(func(ino,fn))
start=ino.index('SYSCALL_DEFINE3(inotify_add_watch,');end=ino.index('\nSYSCALL_DEFINE2(inotify_rm_watch,',start);body=ino[start:end];body=body[body.index('{'):]
parts+=['static int fixture_inotify(int fd,const char *pathname,u32 mask)\n'+body,func(dno,'convert_arg'),r'''
struct dnotify_mark;struct fsnotify_mark;struct dnotify_struct;
typedef void *fl_owner_t;struct task_struct {void *files;};static struct task_struct actor;
#define current (&actor)
static int dir_notify_enable;
#define file_inode(f) ((f)->f_inode)
static void dnotify_flush(struct file *file,fl_owner_t owner) {assert(file==&fdfile && owner==current->files);flushes++;}
static int fixture_dnotify_mark(void) {marks++;return 99;}
''']
body=func(dno,'fcntl_dirnotify');cut=body.index('\t/* expect most fcntl to add new rather than augment old */');prefix=body[:cut]
prefix=prefix.replace('int fcntl_dirnotify(', 'static int fixture_dnotify(',1)+'\t(void)fd;\n\treturn fixture_dnotify_mark();\nout_err:\n\treturn error;\n}'
parts.append(prefix)
parts.append(r'''
static void reset(void) {
 integrity_error=permission_error=0;avc_calls=0;upperrefs=lowerrefs=0;marks=flushes=fdgets=fdputs=0;
 path_error=dac_error=mark_error=badfd=0;upperentry.d_op=NULL;
 upper.private=lower.private=0;upper.i_mode=lower.i_mode=S_IFREG;
 expected_inode=&upper;fdfile.f_op=&inotify_fops;fdfile.f_path.dentry=&upperentry;fdfile.f_inode=&upper;
}
int main(void) {
 assert(security_hook_heads.path_notify.next==&security_hook_heads.path_notify);
 security_add_hooks(selinux_hooks,1);assert(security_hook_heads.path_notify.next==&selinux_hooks[0].list);
 unsigned long permissions=0,inotify_cases=0,dnotify_cases=0;
 const unsigned short classes[]={SECCLASS_FILE,SECCLASS_DIR,SECCLASS_CHR_FILE,SECCLASS_SOCK_FILE,SECCLASS_FIFO_FILE,SECCLASS_LNK_FILE};
 const int errors[]={0,-EACCES,-ENOMEM};
 for(unsigned mask=0;mask<4096;mask++)for(unsigned obj=0;obj<4;obj++)for(unsigned perm=0;perm<4;perm++)
 for(unsigned private=0;private<2;private++)for(unsigned error=0;error<3;error++)for(unsigned cls=0;cls<6;cls++) {
  reset();upper.private=private;uppersec.sclass=classes[cls];permission_error=errors[error];
  u64 events=mask|(perm&1?FS_OPEN_PERM:0)|(perm&2?FS_ACCESS_PERM:0);
  expected_perms=FILE__WATCH|(mask&(FS_ACCESS|FS_CLOSE_NOWRITE)?FILE__WATCH_READS:0);
  int expected=obj||perm?-EOPNOTSUPP:private?0:permission_error;
  int rc=security_path_notify(&fdfile.f_path,events,obj);assert(rc==expected);
  assert(avc_calls==(unsigned)(!obj&&!perm&&!private));permissions++;
 }
 uppersec.sclass=lowersec.sclass=SECCLASS_FILE;
 const u32 masks[]={IN_ACCESS,IN_CLOSE_NOWRITE,IN_ATTRIB,IN_ACCESS|IN_ATTRIB,
                    IN_ACCESS|IN_DONT_FOLLOW,IN_CLOSE_NOWRITE|IN_ONLYDIR};
 for(unsigned m=0;m<ARRAY_SIZE(masks);m++)for(unsigned stacked=0;stacked<2;stacked++)
 for(unsigned private=0;private<2;private++)for(unsigned error=0;error<3;error++)
 for(unsigned pathfail=0;pathfail<2;pathfail++)for(unsigned dacfail=0;dacfail<2;dacfail++)
 for(unsigned markfail=0;markfail<2;markfail++)for(unsigned fd=0;fd<2;fd++)for(unsigned op=0;op<2;op++) {
  reset();upperentry.d_op=stacked?&stacked_ops:NULL;expected_inode=stacked?&lower:&upper;
  upper.private=lower.private=private;permission_error=errors[error];path_error=pathfail?-ENOENT:0;dac_error=dacfail?-EACCES:0;mark_error=markfail?-ENOSPC:0;badfd=fd;
  fdfile.f_op=op?&otherops:&inotify_fops;
  expected_perms=FILE__WATCH|(masks[m]&(IN_ACCESS|IN_CLOSE_NOWRITE)?FILE__WATCH_READS:0);
  int expected=fd?-EBADF:op?-EINVAL:path_error?path_error:dac_error?dac_error:!private&&permission_error?permission_error:mark_error?mark_error:99;
  int rc=fixture_inotify(7,"path",masks[m]);assert(rc==expected && upperrefs==0 && lowerrefs==0);
  int reached=!fd&&!op&&!pathfail&&!dacfail;
  assert(marks==(unsigned)(reached&&(private||!permission_error)));
  assert(avc_calls==(unsigned)(reached&&!private));assert(fdputs==(unsigned)!fd);inotify_cases++;
 }
 for(unsigned arg=0;arg<64;arg++)for(unsigned multi=0;multi<2;multi++)for(unsigned enabled=0;enabled<2;enabled++)
 for(unsigned dir=0;dir<2;dir++)for(unsigned private=0;private<2;private++)for(unsigned error=0;error<3;error++) {
  reset();dir_notify_enable=enabled;upper.i_mode=dir?S_IFDIR:S_IFREG;upper.private=private;permission_error=errors[error];
  u32 flags=arg|(multi?DN_MULTISHOT:0);expected_perms=FILE__WATCH|(arg&DN_ACCESS?FILE__WATCH_READS:0);
  int expected=!enabled?-EINVAL:!arg?0:!dir?-ENOTDIR:!private&&permission_error?permission_error:99;
  int rc=fixture_dnotify(7,&fdfile,flags);assert(rc==expected);
  assert(flushes==(unsigned)(enabled&&!arg));assert(marks==(unsigned)(expected==99));dnotify_cases++;
 }
 reset();integrity_error=-EFAULT;assert(security_path_notify(&fdfile.f_path,FS_ACCESS,0)==-EFAULT && !avc_calls);
 printf("PASS: %lu inode-watch permission, %lu full inotify syscall/canonical-path/refcount, %lu dnotify authorization-prefix scenarios\n",permissions,inotify_cases,dnotify_cases);
 return 0;
}
''')
with tempfile.TemporaryDirectory(prefix='notify-') as d:
 t=Path(d);(t/'test.c').write_text('\n'.join(parts));command=['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-variable','-Wno-unused-but-set-variable','-Wno-sign-compare','-fsanitize=address,undefined',str(t/'test.c'),'-o',str(t/'test')]
 subprocess.run(command,check=True);result=subprocess.run([str(t/'test')],check=True,text=True,capture_output=True);print(result.stdout,end='')
 guard=subprocess.run(command+['-DCONFIG_FANOTIFY=1'],capture_output=True,text=True);assert guard.returncode and 'Fanotify mount/superblock/permission mediation is not backported' in guard.stderr
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files=[a.kernel/x for x in [inopath,dnpath,'include/linux/fsnotify_backend.h','include/linux/security.h','include/linux/lsm_hooks.h','security/security.c',rel+'hooks.c',rel+'include/classmap.h','include/uapi/linux/inotify.h','include/uapi/linux/fcntl.h']]+[a.before/inopath,a.before/dnpath,a.before/(rel+'include/classmap.h'),a.inotify_header]
a.report.write_text(json.dumps({'passed':True,'scope':__doc__,'result':result.stdout.strip(),'class_ids_unchanged':True,'permission_bit_positions_change':True,'original_permission_name_order_preserved':True,'changed_permission_tables':changed,'original_inode_DAC_and_mask_conversion_bodies_preserved':True,'FANOTIFY_enabled_build_rejected':True,'runner_sha256':sha(Path(__file__)),'inputs_sha256':{str(f):sha(f) for f in files},'hardware_tested':False,'live_watch_or_mark_lifecycle_validated':False},indent=2)+'\n')
