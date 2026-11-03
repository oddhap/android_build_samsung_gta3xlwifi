#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual mmap/helper bodies with fixture credentials, inodes and AVC backend.

Checks permission requests, error precedence and audit objects; NOT kernel or
hardware execution. Uses actual classmap tables to derive permission constants.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile


def module(name, filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['before','candidate','modern','report']:
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--cc',default='clang')
    args=p.parse_args()
    if args.report.exists():
        raise FileExistsError('Use a fresh report path')
    surface=module('surface','audit-kernel-policy-surface.py')
    extract=module('extract','test-netlink-xperm24.py').function
    rel='security/selinux/'
    before_table=surface.table(args.before/(rel+'include/classmap.h'),args.cc)
    candidate_table=surface.table(args.candidate/(rel+'include/classmap.h'),args.cc)
    assert list(before_table)==list(candidate_table), 'Class IDs moved'
    changed=[]
    for name, perms in candidate_table.items():
        assert [x for x in perms if x!='map']==before_table[name]
        if perms!=before_table[name]:
            changed.append(name)
            assert perms.index('map')==10, 'MAP must be common across inode/socket classes'
    inputs={}
    runs=[]
    for kind, tree, constants in [('legacy',args.before,before_table),
                                  ('candidate',args.candidate,candidate_table),
                                  ('modern-control-oracle',args.modern,candidate_table)]:
        source=(tree/(rel+'hooks.c')).read_text()
        base=(args.candidate/(rel+'hooks.c')).read_text()
        defs=[]
        for i,(name,perms) in enumerate(constants.items(),1):
            defs.append(f'#define SECCLASS_{name.upper()} {i}')
            for j,perm in enumerate(perms):
                defs.append(f'#define {name.upper()}__{perm.upper()} (1U << {j})')
        if kind=='legacy':defs.append('#define FILE__MAP 0')
        mode={'legacy':0,'candidate':1,'modern-control-oracle':2}[kind]
        parts=[r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;
#define __always_unused __attribute__((unused))
#define unlikely(x) (x)
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_FIXED 16
#define MAP_TYPE 15
#define LSM_AUDIT_DATA_PATH 1
#define LSM_AUDIT_DATA_FILE 2
struct cred {u32 sid;};
struct inode_security_struct {u32 sid;unsigned short sclass;};
struct inode {int private; struct inode_security_struct *i_security;};
struct path {unsigned cookie;};
struct file_security_struct {u32 sid;};
struct file {struct inode *inode;struct path f_path;struct file_security_struct *f_security;};
struct common_audit_data {char type;union {struct path path;struct file *file;} u;};
static struct cred actor={42};
static struct inode_security_struct isec={84,0};
static struct inode node={0,&isec};
static struct file_security_struct fsec={42};
static struct file backing={&node,{0x12345678},&fsec};
static int default_noexec,selinux_checkreqprot;
static int map_error,exec_error,fd_error,file_error;
static char trace[8];static unsigned trace_length;static u32 observed_file_perms;
#define IS_PRIVATE(i) ((i)->private)
#define file_inode(f) ((f)->inode)
#define validate_creds(c) assert((c)==&actor)
static const struct cred *current_cred(void) {return &actor;}
static u32 cred_sid(const struct cred *c) {assert(c==&actor);return c->sid;}
''','\n'.join(defs),f'#define TEST_MODE {mode}',r'''
static int avc_has_perm(u32 s,u32 t,unsigned short c,u32 perms,struct common_audit_data *ad) {
    assert(s==42 && trace_length<sizeof(trace)-1);
    if(c==SECCLASS_PROCESS) {
        assert(t==42 && perms==PROCESS__EXECMEM && ad==NULL);
        trace[trace_length++]='X';return exec_error;
    }
    assert(ad!=NULL);
    if(ad->type==LSM_AUDIT_DATA_PATH) assert(ad->u.path.cookie==backing.f_path.cookie);
    else {assert(TEST_MODE==2 && ad->type==LSM_AUDIT_DATA_FILE && ad->u.file==&backing);}
    if(c==SECCLASS_FD) {
        assert(t==fsec.sid && perms==FD__USE && t!=42);
        trace[trace_length++]='D';return fd_error;
    }
    assert(c==isec.sclass && t==84);
    if(perms==FILE__MAP) {trace[trace_length++]='M';return map_error;}
    assert(perms & FILE__READ);
    observed_file_perms=perms;trace[trace_length++]='F';return file_error;
}
''']
        if kind!='modern-control-oracle':parts.append(extract(source,'cred_has_perm'))
        # These legacy helpers are unchanged in the candidate. The modern oracle
        # supplies mmap/protection bodies, using the legacy audit ABI for helpers.
        parts += [extract(base,'inode_has_perm'),extract(base,'file_has_perm'),
                  extract(source,'file_map_prot_check'),extract(source,'selinux_mmap_file')]
        parts.append(r'''
int main(void) {
    const unsigned classes[]={SECCLASS_FILE,SECCLASS_CHR_FILE,SECCLASS_BLK_FILE,
                              SECCLASS_SOCK_FILE,SECCLASS_NETLINK_ROUTE_SOCKET,SECCLASS_TCP_SOCKET};
    const unsigned flags_list[]={MAP_SHARED,MAP_PRIVATE,MAP_SHARED|MAP_FIXED,MAP_PRIVATE|MAP_FIXED,0};
    const int map_errors[]={0,-EACCES,-ENOMEM},file_errors[]={0,-EACCES,-EIO};
    unsigned long cases=0;
    for(unsigned ci=0;ci<6;ci++)
    for(unsigned hasfile=0;hasfile<2;hasfile++)
    for(unsigned private=0;private<2;private++)
    for(unsigned foreign=0;foreign<2;foreign++)
    for(unsigned prot=0;prot<8;prot++)
    for(unsigned req=0;req<8;req++)
    for(unsigned fi=0;fi<5;fi++)
    for(unsigned nx=0;nx<2;nx++)
    for(unsigned check=0;check<(TEST_MODE==2 ? 1u:2u);check++)
    for(unsigned me=0;me<3;me++)
    for(unsigned xe=0;xe<2;xe++)
    for(unsigned de=0;de<2;de++)
    for(unsigned fe=0;fe<3;fe++) {
        node.private=private;isec.sclass=classes[ci];fsec.sid=foreign ? 90:42;
        default_noexec=nx;selinux_checkreqprot=check;
        map_error=map_errors[me];exec_error=xe ? -EPERM:0;
        fd_error=de ? -EBADF:0;file_error=file_errors[fe];
        memset(trace,0,sizeof(trace));trace_length=0;observed_file_perms=0;
        unsigned effective=check ? req:prot;
        unsigned shared=(flags_list[fi]&MAP_TYPE)==MAP_SHARED;
        char expected_trace[8]={0};unsigned n=0;int expected=0;u32 expected_perms=0;
        if(TEST_MODE && hasfile && !private) {
            expected_trace[n++]='M';expected=map_error;
        }
        if(!expected && nx && (effective&PROT_EXEC) &&
           (!hasfile || private || (!shared && (effective&PROT_WRITE)))) {
            expected_trace[n++]='X';expected=exec_error;
        }
        if(!expected && hasfile && foreign) {
            expected_trace[n++]='D';expected=fd_error;
        }
        if(!expected && hasfile && !private) {
            expected_perms=FILE__READ;
            if(shared && (effective&PROT_WRITE)) expected_perms|=FILE__WRITE;
            if(effective&PROT_EXEC) expected_perms|=FILE__EXECUTE;
            expected_trace[n++]='F';expected=file_error;
        }
        int rc=selinux_mmap_file(hasfile ? &backing:NULL,req,prot,flags_list[fi]);
        assert(rc==expected && !strcmp(trace,expected_trace));
        assert(observed_file_perms==expected_perms);
        cases++;
    }
    printf("PASS: %lu mmap fixture scenarios; mode=%d\n",cases,TEST_MODE);
    return 0;
}
''')
        with tempfile.TemporaryDirectory(prefix='kernel-mmap-') as d:
            dest=Path(d);(dest/'test.c').write_text('\n'.join(parts))
            subprocess.run([args.cc,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined',str(dest/'test.c'),'-o',str(dest/'test')],check=True)
            result=subprocess.run([str(dest/'test')],check=True,capture_output=True,text=True)
        print(kind,result.stdout.strip())
        runs.append({'mode':kind,'result':result.stdout.strip()})
        for name in ['hooks.c','include/classmap.h']:
            path=tree/(rel+name)
            inputs[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
    report={'scope':'Actual mmap/credential/inode/file permission bodies with fixture AVC/audit objects; not whole kernel or live enforcement',
            'passed':True,'runs':runs,'inputs_sha256':inputs,
            'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'class_ids_unchanged':True,'original_named_permission_order_preserved':True,
            'permission_bit_positions_change':True,'classes_with_inserted_common_map':changed,
            'whole_kernel_and_module_abi_validated':False,'hardware_tested':False}
    args.report.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()
