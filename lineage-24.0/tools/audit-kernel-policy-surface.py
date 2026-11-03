#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare declared kernel class/permission tables with actual built policy.

Compiles classmap string tables on the host, not kernel code or enforcement.
Modern kernel tables distinguish kernel classes from userspace SELinux classes.
Missing declarations are review inputs; presence alone does not prove hooks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def table(path, cc):
    source = r'''
#include <stdio.h>
#include <stddef.h>
struct security_class_mapping { const char *name; const char *perms[33]; };
''' + '#include '+json.dumps(str(path.resolve()))+r'''
int main(void) {
    printf("[");
    for (size_t i=0; secclass_map[i].name; i++) {
        if (i) printf(",");
        printf("{\"name\":\"%s\",\"perms\":[",secclass_map[i].name);
        for (size_t j=0; j<33 && secclass_map[i].perms[j]; j++) {
            if (j==32) return 1;
            if (j) printf(",");
            printf("\"%s\"",secclass_map[i].perms[j]);
        }
        printf("]}");
    }
    printf("]\n");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='kernel-classmap-') as d:
        p=Path(d)
        (p/'dump.c').write_text(source)
        subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror',
                        '-Wno-missing-field-initializers','-fsanitize=address,undefined',
                        str(p/'dump.c'),'-o',str(p/'dump')],check=True)
        r=subprocess.run([str(p/'dump')],check=True,capture_output=True,text=True)
    rows=json.loads(r.stdout)
    if len(rows)!=len({x['name'] for x in rows}):
        raise ValueError('Duplicate kernel class name')
    return {x['name']:x['perms'] for x in rows}


def compare(kernel, modern, policy):
    relevant=set(policy) & set(modern)
    return {'missing_kernel_class_declarations':sorted(relevant-set(kernel)),
            'missing_kernel_permission_declarations':{
                n:sorted(set(policy[n])-set(kernel[n]))
                for n in sorted(relevant & set(kernel)) if set(policy[n])-set(kernel[n])},
            'policy_classes_not_in_reference_kernel_table':sorted(set(policy)-set(modern)),
            'kernel_class_count':len(kernel)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['original-header','modern-header','policy','kernel-config','output']:
        p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--candidate-header',type=Path)
    p.add_argument('--cc',default='clang')
    args=p.parse_args()
    if args.output.exists():
        raise FileExistsError('Use a fresh report path')
    policy=json.loads(args.policy.read_text())
    original=table(args.original_header,args.cc)
    modern=table(args.modern_header,args.cc)
    config=args.kernel_config.read_text()
    names=['PERF_EVENTS','USERFAULTFD','FANOTIFY','FANOTIFY_ACCESS_PERMISSIONS',
           'BPF_SYSCALL','USER_NS','IP_SCTP','IP_DCCP','COMPAT','ANDROID_BINDER_DEVICES',
           'ANDROID_BINDER_IPC_32BIT','ALWAYS_ENFORCE','SECURITY_SELINUX_DEVELOP']
    settings={}
    for name in names:
        m=re.search(r'^CONFIG_'+name+r'=(.*)$',config,re.M)
        settings[name]=m[1] if m else ('n' if '# CONFIG_'+name+' is not set' in config else 'not listed')
    result={'scope':'Static declaration comparison and config review inputs only; NOT hook/enforcement validation',
            'original':compare(original,modern,policy['classes']),
            'active_policycaps':policy['policycaps'], 'kernel_config':settings,
            'policy_cil_sha256':policy['source_sha256'],
            'inputs_sha256':{str(x):sha(x) for x in
                            [args.original_header,args.modern_header,args.policy,args.kernel_config]},
            'source_or_device_modified':False,'hardware_tested':False,
            'kernel_boot_or_security_approved':False}
    if args.candidate_header:
        candidate=table(args.candidate_header,args.cc)
        result['isolated_candidate']=compare(candidate,modern,policy['classes'])
        result['inputs_sha256'][str(args.candidate_header)]=sha(args.candidate_header)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print('Original missing kernel classes:',len(result['original']['missing_kernel_class_declarations']))
    print('Original classes with missing permissions:',len(result['original']['missing_kernel_permission_declarations']))
    print('Review required; declaration presence is NOT enforcement proof.')


if __name__=='__main__':
    main()
