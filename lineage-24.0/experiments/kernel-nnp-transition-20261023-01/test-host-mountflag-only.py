#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise extracted production NNP/nosuid checks, NOT a live kernel.

Modern oracle is the pinned Android-16 check_nnp_nosuid. Its mount detection is
normalized to the existing 4.4 MNT_NOSUID expression for this control-flow test;
this is NOT a claim of modern mnt_may_suid/user/mount-namespace equivalence.
AVC, credentials, mounts, bitmap, and bounded-transition decisions are fixtures.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


def function(text, name, returns):
    m = re.search(r'^static ' + returns + ' ' + name + r'\(.*?^}', text, re.M | re.S)
    if not m:
        raise ValueError('Missing actual production function: ' + name)
    return m.group()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['staged', 'baseline', 'upstream']:
        p.add_argument(name, type=Path)
    p.add_argument('--cc', default='cc')
    a = p.parse_args()
    paths = {n: getattr(a, n)/'security/selinux' for n in ['staged', 'baseline', 'upstream']}
    hooks = {n: (d/'hooks.c').read_text() for n, d in paths.items()}
    funcs = {n: function(t, 'check_nnp_nosuid', 'int') for n, t in hooks.items()}
    # No deletion of ordinary exec/entrypoint/transition/audit checks or other hooks.
    assert hooks['staged'].replace(funcs['staged'], 'CHECK') == hooks['baseline'].replace(funcs['baseline'], 'CHECK')
    services = (paths['staged']/'ss/services.c').read_text()
    loadcaps = function(services, 'security_load_policycaps', 'void')
    header = (paths['staged']/'include/security.h').read_text()
    enum = re.search(r'/\* Policy capabilities \*/\s*(enum \{.*?\};)', header, re.S).group(1)
    fs = (paths['staged']/'selinuxfs.c').read_text()
    names = re.search(r'^static char \*policycap_names\[\] = \{.*?^};', fs, re.M | re.S).group()
    assert 'iter < ARRAY_SIZE(policycap_names) && policycap_names[iter]' in fs
    assert header.count('extern int selinux_policycap_nnp_nosuid_transition;') == 1
    assert services.count('int selinux_policycap_nnp_nosuid_transition;') == 1
    assert loadcaps.count('POLICYDB_CAPABILITY_NNP_NOSUID_TRANSITION') == 1
    # Preserve 4.4 mount semantics explicitly; test the permission decision, not
    # the newer kernel's user/mount namespace implementation.
    oracle = funcs['upstream'].replace('!mnt_may_suid(bprm->file->f_path.mnt)',
        '(bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID)')
    assert oracle != funcs['upstream']
    source = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
typedef uint32_t u32;
#define LSM_UNSAFE_NO_NEW_PRIVS 4
#define MNT_NOSUID 2
#define SECCLASS_PROCESS2 999
#define PROCESS2__NNP_TRANSITION 1
#define PROCESS2__NOSUID_TRANSITION 2
struct vfsmount { unsigned mnt_flags; };
struct path { struct vfsmount *mnt; };
struct file { struct path f_path; };
struct linux_binprm { unsigned unsafe; struct file *file; };
struct task_security_struct { u32 sid; };
struct ebitmap { uint64_t bits; };
struct { struct ebitmap policycaps; int android_netlink_route; } policydb;
int selinux_policycap_netpeer, selinux_policycap_openperm;
int selinux_policycap_alwaysnetwork, selinux_policycap_nnp_nosuid_transition;
int selinux_android_netlink_route;
static unsigned nlmsg_calls, avc_calls, bound_calls, allowed, requested;
static int forced_avc_error, bounded_error;
static int ebitmap_get_bit(struct ebitmap *b, unsigned n) { return (b->bits >> n) & 1; }
static void selinux_nlmsg_init(void) { ++nlmsg_calls; }
static int avc_has_perm(u32 source, u32 target, unsigned cls, u32 av, void *audit) {
 assert(source == 10 && target == 20 && cls == SECCLASS_PROCESS2 && audit == NULL);
 ++avc_calls; requested = av;
 return forced_avc_error ? forced_avc_error : ((av & allowed) == av ? 0 : -EACCES);
}
static int security_bounded_transition(u32 source, u32 target) {
 assert(source == 10 && target == 20); ++bound_calls; return bounded_error;
}
#define selinux_policycap_nnp_nosuid_transition() (selinux_policycap_nnp_nosuid_transition)
'''
    source += enum + '\n' + names + '\n' + loadcaps + '\n'
    for name, text in [('candidate', funcs['staged']), ('legacy', funcs['baseline']), ('oracle', oracle)]:
        source += text.replace('check_nnp_nosuid(', name + '(') + '\n'
    # Actual old/new names and permission tables; normalize ONLY the implicit
    # all-zero terminal sentinel for strict host -Wmissing-field-initializers.
    # No compiler warning is disabled and no production entry is changed.
    maps = {n: (paths[n]/'include/classmap.h').read_text().replace(
        '{ NULL }', '{ NULL, { NULL } }') for n in ['baseline', 'staged']}
    source += r'''
struct security_class_mapping { const char *name; const char *perms[33]; };
#define secclass_map old_map
''' + maps['baseline'] + r'''
#undef secclass_map
#define secclass_map new_map
''' + maps['staged'] + r'''
#undef secclass_map
static void same(const char *a, const char *b) { assert((!a && !b) || (a && b && !strcmp(a,b))); }
int main(void) {
 unsigned classes=0, cases=0, legacy_differences=0;
 for(;old_map[classes].name;++classes) {
  same(old_map[classes].name,new_map[classes].name);
  for(unsigned j=0;j<33;++j)same(old_map[classes].perms[j],new_map[classes].perms[j]);
 }
 same(new_map[classes].name,"process2");
 same(new_map[classes].perms[0],"nnp_transition");
 same(new_map[classes].perms[1],"nosuid_transition");
 assert(!new_map[classes].perms[2] && !new_map[classes+1].name);
 assert(POLICYDB_CAPABILITY_NETPEER==0 && POLICYDB_CAPABILITY_OPENPERM==1);
 assert(POLICYDB_CAPABILITY_REDHAT1==2 && POLICYDB_CAPABILITY_ALWAYSNETWORK==3);
 assert(POLICYDB_CAPABILITY_NNP_NOSUID_TRANSITION==5 && POLICYDB_CAPABILITY_MAX_UNUSED_PLACEHOLDER==6);
 assert(!policycap_names[4]);
 same(policycap_names[5],"nnp_nosuid_transition");
 for(unsigned bits=0;bits<(1U<<13);++bits) {
  policydb.policycaps.bits=bits; policydb.android_netlink_route=bits%3;
  security_load_policycaps();
  assert(selinux_policycap_netpeer==!!(bits&1));
  assert(selinux_policycap_openperm==!!(bits&2));
  assert(selinux_policycap_alwaysnetwork==!!(bits&8));
  assert(selinux_policycap_nnp_nosuid_transition==!!(bits&32));
  assert(selinux_android_netlink_route==(int)(bits%3));
 }
 assert(nlmsg_calls==(1U<<13));
 const int errors[]={0,-EPERM,-EACCES,-EIO};
 for(unsigned cap=0;cap<2;++cap)
 for(unsigned unsafe=0;unsafe<8;++unsafe)
 for(unsigned flags=0;flags<4;++flags)
 for(unsigned same_sid=0;same_sid<2;++same_sid)
 for(allowed=0;allowed<4;++allowed)
 for(unsigned ae=0;ae<4;++ae)
 for(unsigned be=0;be<4;++be) {
  struct vfsmount mnt={flags}; struct file file={{&mnt}};
  struct linux_binprm bprm={unsafe,&file};
  struct task_security_struct from={10},to={same_sid?10:20};
  selinux_policycap_nnp_nosuid_transition=cap;
  forced_avc_error=errors[ae]; bounded_error=errors[be];
  unsigned need=(unsafe&LSM_UNSAFE_NO_NEW_PRIVS?1:0)|(flags&MNT_NOSUID?2:0);
  avc_calls=bound_calls=requested=0;
  int result=candidate(&bprm,&from,&to);
  assert(avc_calls==(unsigned)(cap && need && !same_sid));
  if(avc_calls)assert(requested==need);
  unsigned ca=avc_calls,cb=bound_calls;
  avc_calls=bound_calls=requested=0;
  int reference=oracle(&bprm,&from,&to);
  assert(result==reference && avc_calls==ca && bound_calls==cb);
  int old=legacy(&bprm,&from,&to);
  if(old!=reference)++legacy_differences;
  if(!cap)assert(result==old);
  ++cases;
 }
 // Concrete modern-policy nosuid authorization with no bounded relationship.
 struct vfsmount mnt={MNT_NOSUID}; struct file file={{&mnt}};
 struct linux_binprm bprm={0,&file};
 struct task_security_struct from={10},to={20};
 selinux_policycap_nnp_nosuid_transition=1;
 forced_avc_error=0; bounded_error=-EACCES; allowed=2;
 assert(candidate(&bprm,&from,&to)==0);
 assert(legacy(&bprm,&from,&to)==-EACCES);
 // Both protections active: a grant of just one must never authorize the pair.
 bprm.unsafe=LSM_UNSAFE_NO_NEW_PRIVS;
 allowed=1;assert(candidate(&bprm,&from,&to)==-EPERM);
 allowed=2;assert(candidate(&bprm,&from,&to)==-EPERM);
 allowed=3;assert(candidate(&bprm,&from,&to)==0);
 printf("PASS: %u decision cases against actual modern function; %u original-kernel differences; "
        "%u original classes/permissions unchanged; 8192 real load-helper bitmap combinations\n",
        cases,legacy_differences,classes);
 puts("Fixtures, NOT kernel/AVC/runtime execution; modern mount-namespace semantics NOT claimed");
 return 0;
}
'''
    source = source.replace('POLICYDB_CAPABILITY_MAX_UNUSED_PLACEHOLDER', '__POLICYDB_CAPABILITY_MAX')
    with tempfile.TemporaryDirectory(prefix='kernel-nnp-') as d:
        c, exe = Path(d)/'test.c', Path(d)/'test'
        c.write_text(source)
        subprocess.run([a.cc, '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                        str(c), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    for name, path in paths.items():
        print(name, 'hooks SHA-256:', hashlib.sha256((path/'hooks.c').read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
