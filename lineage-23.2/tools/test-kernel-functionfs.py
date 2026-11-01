#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extracted FunctionFS/SELinux/VFS labeling tests, NOT a running kernel.

Actual production label-selection, relabel authorization, VFS fallback and
in-core SID update functions; fixture objects, locks, credentials, AVC, context
parser, audit, notifications. Pinned modern helper used as mount-label oracle.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


def extract(text, name):
    m = re.search(r'^(?:static )?(?:inline )?(?:int|void)\s*\n?' + re.escape(name) + r'\(.*?^}', text, re.M | re.S)
    if not m:
        raise ValueError('Missing production function: ' + name)
    return m.group()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ['staged', 'baseline', 'upstream']:
        p.add_argument(n, type=Path)
    p.add_argument('--cc', default='cc')
    a = p.parse_args()
    roots = {n: getattr(a, n)/'security/selinux' for n in ['staged', 'baseline', 'upstream']}
    texts = {n: (r/'hooks.c').read_text() for n, r in roots.items()}
    selected = ['selinux_is_sblabel_mnt', 'selinux_inode_setxattr', 'selinux_inode_setsecurity']
    f = {n: extract(texts['staged'], n) for n in selected}
    special = extract(texts['staged'], 'selinux_is_genfs_special_handling')
    oracle = extract(texts['upstream'], 'selinux_is_genfs_special_handling').replace(
        'selinux_is_genfs_special_handling(', 'modern_special(')
    oracle += '\n' + extract(texts['upstream'], 'selinux_is_sblabel_mnt').replace(
        'selinux_is_sblabel_mnt(', 'modern_label(').replace(
        'selinux_is_genfs_special_handling(', 'modern_special(')
    # Compare all other hook bytes to the already reviewed NNP02 baseline.
    new = texts['staged'].replace(special+'\n\n', '')
    new = new.replace(f['selinux_is_sblabel_mnt'], extract(texts['baseline'], 'selinux_is_sblabel_mnt'))
    addition = ' ||\n\t    (selinux_policycap_functionfs_seclabel &&\n\t     !strcmp(sb->s_type->name, "functionfs"))'
    assert new.count(addition) == 1
    new = new.replace(addition, '')
    # Optional narrowly scoped audit-size fix is verified, never hidden.
    base_relabel = extract(texts['baseline'], 'selinux_inode_setxattr')
    assert f['selinux_inode_setxattr'] in [base_relabel, base_relabel.replace('if (value) {', 'if (value && size) {')]
    new = new.replace(f['selinux_inode_setxattr'], base_relabel)
    assert new == texts['baseline'], 'Unexpected unrelated hook changes'
    # Actual mount-option classification block, wrapped only for host invocation.
    begin = texts['staged'].index('\tif (strcmp(sb->s_type->name, "proc") == 0)')
    end = texts['staged'].index('\n\tif (!sbsec->behavior)', begin)
    flags = texts['staged'][begin:end]
    xattr = (a.baseline/'fs/xattr.c').read_text()
    vfs = extract(xattr, '__vfs_setxattr_noperm') + '\n' + extract(xattr, 'vfs_setxattr')
    parser = (roots['baseline']/'ss/services.c').read_text()
    assert re.search(r'if \(!scontext_len\)\s*return -EINVAL;', parser)
    ffs = (a.baseline/'drivers/usb/gadget/function/f_fs.c').read_text()
    assert re.search(r'ffs_sb_make_inode\(sb, data, fops, NULL,', ffs)
    h = (roots['staged']/'include/security.h').read_text()
    defines = '\n'.join(l for l in h.splitlines() if l.startswith('#define SECURITY_FS_USE_'))
    # The unchanged setsecurity flags parameter is unused in production too.
    setsecurity = f['selinux_inode_setsecurity'].replace('{', '{\n\t(void)flags;', 1)
    source = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
typedef uint32_t u32;
#define BUILD_BUG_ON(c) _Static_assert(!(c), "new fs behavior needs review")
#define SBLABEL_MNT 16
#define SE_SBGENFS 1024
#define SE_SBPROC 512
#define XATTR_NAME_SELINUX "security.selinux"
#define XATTR_SELINUX_SUFFIX "selinux"
#define XATTR_SECURITY_PREFIX "security."
#define XATTR_SECURITY_PREFIX_LEN 9
#define FILE__RELABELFROM 1
#define FILE__RELABELTO 2
#define FILESYSTEM__ASSOCIATE 4
#define SECCLASS_FILESYSTEM 9
#define LSM_AUDIT_DATA_DENTRY 1
#define CAP_MAC_ADMIN 33
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define AUDIT_SELINUX_ERR 1
#define MAY_WRITE 2
#define S_NOSEC 1
struct inode;
struct dentry;
struct inode_operations { int (*setxattr)(struct dentry*,const char*,const void*,size_t,int); };
struct inode_security_struct { u32 sid; unsigned sclass, initialized; };
struct superblock_security_struct { unsigned behavior,flags; u32 sid; };
struct file_system_type { const char *name; };
struct super_block { struct superblock_security_struct *s_security; struct file_system_type *s_type; };
struct inode { struct inode_security_struct *i_security; struct super_block *i_sb;
 unsigned i_mode,i_flags,i_mutex; struct inode_operations *i_op; unsigned long i_ino; };
struct dentry { struct inode *d_inode; };
struct common_audit_data { unsigned type; union { struct dentry *dentry; } u; };
struct audit_buffer { int unused; };
struct { void *audit_context; } current_fixture;
#define current (&current_fixture)
#define d_backing_inode(d) ((d)->d_inode)
#define selinux_superblock(sb) ((sb)->s_security)
#define selinux_policycap_cgroupseclabel() 0
int selinux_policycap_functionfs_seclabel;
static int owner_ok,unix_error,parse_error,force_error,mac_admin,transition_error;
static unsigned denied, writes,notifications,avc_seen,parse_calls,force_calls;
static unsigned audit_length,lock_depth;
static u32 current_sid(void) { return 100; }
static int inode_owner_or_capable(struct inode *i) { (void)i;return owner_ok; }
static int capable(unsigned cap) { assert(cap==CAP_MAC_ADMIN);return mac_admin; }
static int avc_has_perm(u32 s,u32 t,unsigned cls,u32 av,struct common_audit_data *ad) {
 (void)s;(void)t;(void)cls;assert(ad);avc_seen|=av;return denied&av?-EACCES:0;
}
static int security_sid_to_context(u32 sid,char **s,u32 *len) {
 (void)sid;*s=malloc(4);assert(*s);memcpy(*s,"old",4);*len=4;return 0;
}
static int security_context_to_sid(const void *v,size_t n,u32 *sid,int gfp) {
 (void)gfp;++parse_calls;if(parse_error)return parse_error;
 if(!v||!n)return -EINVAL;
 *sid=200;return 0;
}
static int security_context_to_sid_force(const void *v,size_t n,u32 *sid) {
 ++force_calls;
 if(force_error)return force_error;
 if(!v||!n)return -EINVAL;
 *sid=200;return 0;
}
static int security_validate_transition(u32 a,u32 b,u32 c,unsigned cls) {
 (void)a;(void)b;(void)c;(void)cls;return transition_error;
}
static struct audit_buffer *audit_log_start(void *ctx,int gfp,int type) {
 (void)ctx;(void)gfp;(void)type;return NULL;
}
static void audit_log_format(struct audit_buffer *b,const char *f,...) { (void)b;(void)f; }
static void audit_log_n_untrustedstring(struct audit_buffer *b,const void *v,size_t n) {
 (void)b;if(n)assert(v);audit_length=(unsigned)n;
}
static void audit_log_end(struct audit_buffer *b) { (void)b; }
#define kfree free
#define SE_LOG(...) ((void)0)
static void dump_stack(void) {}
static void fslog_kmsg_selog(const char *name,int n) { (void)name;(void)n; }
static unsigned inode_mode_to_security_class(unsigned mode) { (void)mode;return 3; }
'''
    legacy = extract(texts['baseline'], 'selinux_is_sblabel_mnt').replace('selinux_is_sblabel_mnt(', 'legacy_label(')
    source += defines + '\n' + special + '\n' + f['selinux_is_sblabel_mnt'] + '\n' + oracle + '\n' + legacy + '\n'
    source += 'static void genfs_flags(struct super_block *sb) {\nstruct superblock_security_struct *sbsec=sb->s_security;\n' + flags + '\n}\n'
    source += f['selinux_inode_setxattr'] + '\n' + setsecurity + r'''
static int security_inode_setxattr(struct dentry *d,const char*n,const void*v,size_t size,int flags) {
 return selinux_inode_setxattr(d,n,v,size,flags);
}
static int security_inode_setsecurity(struct inode*i,const char*n,const void*v,size_t size,int flags) {
 ++writes;return selinux_inode_setsecurity(i,n,v,size,flags);
}
static int selinux_inode_setotherxattr(struct dentry *d,const char *n);
static int xattr_permission(struct inode*i,const char*n,int mode) { (void)i;(void)n;assert(mode==MAY_WRITE);return unix_error; }
static void mutex_lock(unsigned *m) { (void)m;assert(!lock_depth);++lock_depth; }
static void mutex_unlock(unsigned *m) { (void)m;assert(lock_depth==1);--lock_depth; }
static void fsnotify_xattr(struct dentry*d) { (void)d;++notifications; }
static void security_inode_post_setxattr(struct dentry*d,const char*n,const void*v,size_t s,int f) {
 (void)d;(void)n;(void)v;(void)s;(void)f;assert(0);
}
''' + vfs + r'''
int main(void) {
 const char *names[]={"functionfs","sysfs","pstore","debugfs","tracefs","rootfs",
 "ext4","tmpfs","cgroup","cgroup2","configfs","binder","proc","bpf","functionfs_bad","FUNCTIONFS",""};
 unsigned mount_cases=0,path_cases=0;
 struct superblock_security_struct sec={0};
 struct file_system_type type={"functionfs"}; struct super_block sb={&sec,&type};
 for(unsigned cap=0;cap<2;++cap)for(unsigned b=0;b<10;++b)
 for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i) {
  selinux_policycap_functionfs_seclabel=cap;sec.behavior=b;type.name=names[i];sec.flags=0;
  int expected=modern_label(&sb);
  if(!cap&&b==SECURITY_FS_USE_GENFS&&!strcmp(type.name,"functionfs"))expected=0;
  assert(selinux_is_sblabel_mnt(&sb)==expected);
  if(b==SECURITY_FS_USE_MNTPOINT||b==SECURITY_FS_USE_NONE||b==0||b>7)assert(!expected);
  genfs_flags(&sb);
  if(!strcmp(type.name,"functionfs"))assert(!!(sec.flags&SE_SBGENFS)==cap);
  if(!strcmp(type.name,"functionfs_bad"))assert(!(sec.flags&SE_SBGENFS));
  ++mount_cases;
 }
 type.name="functionfs";sec.behavior=SECURITY_FS_USE_GENFS;
 selinux_policycap_functionfs_seclabel=1;
 assert(!legacy_label(&sb)&&selinux_is_sblabel_mnt(&sb));
 type.name="sysfs";sec.behavior=SECURITY_FS_USE_MNTPOINT;
 assert(legacy_label(&sb)&&!selinux_is_sblabel_mnt(&sb));
 type.name="functionfs";
 struct inode_operations ops={0};struct inode_security_struct isec={77,3,1};
 struct inode inode={&isec,&sb,0600,0,0,&ops,1};struct dentry d={&inode};
 for(unsigned cap=0;cap<2;++cap)for(unsigned b=1;b<=7;++b)
 for(unsigned owner=0;owner<2;++owner)for(unsigned unix_deny=0;unix_deny<2;++unix_deny)
 for(unsigned deny=0;deny<8;++deny)for(unsigned transition=0;transition<2;++transition) {
  selinux_policycap_functionfs_seclabel=cap;sec.behavior=b;
  sec.flags=selinux_is_sblabel_mnt(&sb)?SBLABEL_MNT:0;
  owner_ok=owner;unix_error=unix_deny?-EACCES:0;denied=deny;
  transition_error=transition?-EPERM:0;parse_error=force_error=mac_admin=0;
  writes=notifications=avc_seen=parse_calls=force_calls=0;isec.sid=77;
  int expected=unix_error;
  if(!expected&&!(sec.flags&SBLABEL_MNT))expected=-EOPNOTSUPP;
  if(!expected&&!owner)expected=-EPERM;
  if(!expected&&(deny&FILE__RELABELFROM))expected=-EACCES;
  if(!expected&&(deny&FILE__RELABELTO))expected=-EACCES;
  if(!expected&&transition_error)expected=transition_error;
  if(!expected&&(deny&FILESYSTEM__ASSOCIATE))expected=-EACCES;
  int rc=vfs_setxattr(&d,XATTR_NAME_SELINUX,"target",6,0);
  assert(rc==expected && !lock_depth);
  assert(writes==(unsigned)!expected && notifications==(unsigned)!expected);
  assert(isec.sid==(expected?77:200));
  ++path_cases;
 }
 sec.behavior=SECURITY_FS_USE_GENFS;sec.flags=SBLABEL_MNT;
 owner_ok=1;unix_error=denied=transition_error=mac_admin=force_error=0;
 const char payload[]="bad";
 for(unsigned len=0;len<=sizeof(payload);++len) {
  parse_error=-EINVAL;isec.sid=77;writes=notifications=0;audit_length=999;
  assert(vfs_setxattr(&d,XATTR_NAME_SELINUX,payload,len,0)==-EINVAL);
  assert(!writes&&!notifications&&isec.sid==77);
  assert(audit_length==(len&&payload[len-1]=='\0'?len-1:len));
 }
 parse_error=-EINVAL;mac_admin=1;force_error=-EIO;writes=0;
 assert(vfs_setxattr(&d,XATTR_NAME_SELINUX,payload,sizeof(payload),0)==-EIO&&!writes);
 // MAC_ADMIN's LSM force path does NOT make an invalid in-core context valid.
 force_error=0;notifications=0;
 assert(vfs_setxattr(&d,XATTR_NAME_SELINUX,payload,sizeof(payload),0)==-EINVAL);
 assert(isec.sid==77&&writes==1&&!notifications);
 parse_error=0;assert(vfs_setxattr(&d,XATTR_NAME_SELINUX,payload,sizeof(payload),0)==0);
 assert(isec.sid==200&&writes==2&&notifications==1);
 parse_error=-EINVAL;mac_admin=0;writes=notifications=0;isec.sid=77;
 assert(vfs_setxattr(&d,XATTR_NAME_SELINUX,NULL,0,0)==-EINVAL);
 assert(isec.sid==77&&!writes&&!notifications&&audit_length==0);
 puts("PASS: authorization-before-in-core SID update; empty/malformed/forced-context errors preserved");
 printf("PASS: %u mount classification/oracle cases; %u actual VFS/SELinux authorization paths; NOT kernel/USB execution\n",mount_cases,path_cases);
 return 0;
}
'''
    # Forward declaration needed by the unchanged production relabel hook.
    decl='static int selinux_inode_setotherxattr(struct dentry *d,const char *n) { (void)d;(void)n;return -EOPNOTSUPP; }\n'
    # The existing relabel hook also intentionally ignores xattr flags.
    relabel = f['selinux_inode_setxattr'].replace('{', '{\n\t(void)flags;', 1)
    source = source.replace(f['selinux_inode_setxattr'], decl + relabel, 1)
    with tempfile.TemporaryDirectory(prefix='functionfs-policy-') as d:
        c, exe = Path(d)/'test.c', Path(d)/'test'
        c.write_text(source)
        subprocess.run([a.cc, '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(c), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    for n in selected:
        print(n,hashlib.sha256(f[n].encode()).hexdigest())


if __name__ == '__main__':
    main()
