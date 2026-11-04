#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Probe the exact old kernel AVTAB reader using xperms from an actual policy.

Compiles an extracted production C function with fixture I/O/type-table checks.
NOT executing a kernel or proving whole-policy loading/enforcement. Exit 1 means
modern record incompatibility was reproduced; it is never converted into PASS.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(text, name):
    path = Path(__file__).with_name('test-netlink-xperm24.py')
    spec = importlib.util.spec_from_file_location('extract', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.function(text, name)


PREAMBLE = r'''
/* Kernel function/structures extracted from GPL-2.0 production sources.
 * Only the surrounding host I/O and type-table storage are fixtures. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
typedef uint16_t u16; typedef uint32_t u32; typedef uint8_t u8;
typedef uint16_t __le16; typedef uint32_t __le32;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error This host probe requires a little-endian host
#endif
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define KERN_ERR ""
#define pr_info(...) ((void)0)
static int printk(const char *f, ...) { (void)f;return 0; }
struct extended_perms_data { u32 p[8]; };
struct avtab { int unused; };
struct policydb { u32 policyvers;u32 types;u32 classes; };
struct input { const unsigned char *data;size_t length;size_t position; };
static int next_entry(void *dest,void *opaque,size_t n) {
 struct input *f=opaque;
 if(n>f->length-f->position)return -EINVAL;
 memcpy(dest,f->data+f->position,n);f->position+=n;return 0;
}
static int policydb_type_isvalid(struct policydb *p,u32 n) { return n>0&&n<=p->types; }
static int policydb_class_isvalid(struct policydb *p,u32 n) { return n>0&&n<=p->classes; }
'''
TAIL = r'''
static struct avtab_extended_perms last;
static int inserted;
static int capture(struct avtab *a,struct avtab_key *k,struct avtab_datum *d,void *arg) {
 (void)a;(void)arg;
 if(k->specified&AVTAB_XPERMS)last=*d->u.xperms;
 ++inserted;return 0;
}
int main(int argc,char **argv) {
 if(argc!=5)return 2;
 FILE *f=fopen(argv[1],"rb");if(!f)return 2;
 unsigned char b[4096];size_t n=fread(b,1,sizeof(b),f);int more=fgetc(f);fclose(f);
 if(more!=EOF)return 2;
 struct input in={b,n,0};struct avtab a={0};
 struct policydb p={30,(u32)strtoul(argv[2],NULL,10),(u32)strtoul(argv[3],NULL,10)};
 int rc=0;unsigned count=(unsigned)strtoul(argv[4],NULL,10);
 if(!count||count>4)return 2;
 for(unsigned i=0;i<count;++i) { rc=avtab_read_item(&a,&in,&p,capture,NULL);if(rc)break; }
 printf("{\"return\":%d,\"consumed\":%zu,\"record_bytes\":%zu,"
        "\"parsed_kind\":%u,\"parsed_driver\":%u,\"compat_mode\":%u,\"inserted\":%d}\n",
        rc,in.position,n,last.specified,last.driver,avtab_android_m_compat,inserted);
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspector', type=Path, required=True)
    parser.add_argument('--cc', default='cc')
    parser.add_argument('kernel', type=Path)
    parser.add_argument('policy', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    kernel, policy, output = args.kernel.resolve(), args.policy.resolve(), args.output.resolve()
    if output == kernel or output.is_relative_to(kernel) or output == policy.parent or output.is_relative_to(policy.parent):
        raise ValueError('Fresh scratch must stay outside protected kernel/policy input trees')
    output.mkdir(parents=True, exist_ok=False)
    report = {'passed': False, 'actual_kernel_execution': False,
              'whole_policy_load_proven': False, 'selinux_enforcement_proven': False,
              'checked_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        inspection = subprocess.check_output([str(args.inspector.resolve()), str(policy)], text=True)
        data = json.loads(inspection)
        (output / 'binary-inspection.json').write_text(inspection)
        if data['policy_binary_version'] != 30:
            raise ValueError('This probe targets the actual version-30 old kernel policy')
        cfile, header = kernel/'security/selinux/ss/avtab.c', kernel/'security/selinux/ss/avtab.h'
        src, h = cfile.read_text(), header.read_text()
        structures = h[h.index('struct avtab_key {'):h.index('struct avtab_node {')]
        support = src[src.index('#define AVTAB_OPTYPE_ALLOWED'):src.index('int avtab_read_item(')]
        versions = (kernel/'security/selinux/include/security.h').read_text()
        defs = '\n'.join(re.findall(r'^#define POLICYDB_VERSION_(?:AVTAB|XPERMS_IOCTL)\s+\d+.*$', versions, re.M))
        if len(defs.splitlines()) != 2:
            raise ValueError('Missing actual kernel binary version definitions')
        extracted = function(src, 'avtab_read_item')
        unit = output/'reader.c'
        unit.write_text(PREAMBLE + structures + defs + '\n' + support + extracted + '\n' + TAIL)
        exe = output/'reader'
        command = [args.cc, '-std=gnu11', '-Wall', '-Werror', '-g', '-fsanitize=address,undefined',
                   '-fno-omit-frame-pointer', str(unit), '-o', str(exe)]
        subprocess.run(command, check=True, capture_output=True, text=True)
        cases = []

        def run(name, record, records=1):
            f = output/(name + '.record')
            f.write_bytes(record)
            result = subprocess.run([str(exe), str(f), str(data['type_count']), str(data['class_count']), str(records)],
                                    check=True, capture_output=True, text=True)
            r = json.loads(result.stdout)
            cases.append({'name': name, **r})
            return r

        key = struct.pack('<4H', 1, 1, 1, 0x100)
        normal = key + bytes([1, 0x70]) + struct.pack('<8I', 1, 0, 0, 0, 0, 0, 0, 0)
        r = run('control-normal-ioctl', normal)
        if not (r['return'] == 0 and r['consumed'] == len(normal) and r['parsed_kind'] == 1
                and r['parsed_driver'] == 0x70 and r['compat_mode'] == 0):
            raise ValueError('Normal-format control failed')
        native_driver = key + bytes([2, 0]) + struct.pack('<8I', 1, 0, 0, 0, 0, 0, 0, 0)
        r = run('control-native-ioctl-driver', native_driver)
        if not (r['return'] == 0 and r['consumed'] == len(native_driver) and r['parsed_kind'] == 2
                and r['parsed_driver'] == 0 and r['compat_mode'] == 0):
            raise ValueError('Native driver-format control failed')
        legacy = key + bytes([0x89]) + struct.pack('<8I', 1, 0, 0, 0, 0, 0, 0, 0)
        r = run('control-android-m-ioctl', legacy)
        if not (r['return'] == 0 and r['consumed'] == len(legacy) and r['parsed_driver'] == 0x89
                and r['parsed_kind'] == 1 and r['compat_mode'] == 1):
            raise ValueError('Legacy Android-M control failed')
        compatible = True
        for i, sample in enumerate(data['nlmsg_samples']):
            record = struct.pack('<4H', *(sample[k] for k in ['source_type', 'target_type', 'target_class', 'key_specified']))
            record += bytes([sample['xperm_specified'], sample['driver']]) + struct.pack('<8I', *sample['perms'])
            r = run('actual-nlmsg-' + str(i), record)
            correct = (r['return'] == 0 and r['consumed'] == len(record)
                       and r['parsed_kind'] == sample['xperm_specified']
                       and r['parsed_driver'] == sample['driver'] and r['compat_mode'] == 0)
            cases[-1]['modern_format_correct'] = correct
            cases[-1]['real_binary_sample'] = sample
            compatible &= correct
            r = run('actual-nlmsg-followed-by-ioctl-' + str(i), record + normal, 2)
            sequence_correct = (r['return'] == 0 and r['consumed'] == len(record + normal)
                                and r['inserted'] == 2 and r['compat_mode'] == 0
                                and r['parsed_kind'] == 1 and r['parsed_driver'] == 0x70)
            cases[-1]['modern_sequence_correct'] = sequence_correct
            compatible &= sequence_correct
            if i == 0:
                for length in [0, 7, 8, 9, 10, 41]:
                    r = run('truncated-native-' + str(length), record[:length])
                    if r['return'] == 0:
                        compatible = False
                        cases[-1]['truncated_native_was_wrongly_accepted'] = True
        if not data['nlmsg_samples']:
            raise ValueError('No actual new-format records found; not a valid reproducer')
        report.update({'passed': compatible, 'modern_xperm_record_compatible': compatible,
                       'controls_passed': True, 'cases': cases,
                       'policy_sha256': sha(policy), 'inspector_sha256': sha(args.inspector),
                       'kernel_reader_sha256': sha(cfile), 'kernel_header_sha256': sha(header),
                       'extracted_function_sha256': hashlib.sha256(extracted.encode()).hexdigest(),
                       'compile_command': command, 'xperm_kind_counts': data['xperm_kind_counts'],
                       'netlink_xperm_enabled_in_input': data.get('netlink_xperm_enabled'),
                       'enabled_policy_capabilities': data.get('enabled_policy_capabilities'),
                       'type_class_table_checks_and_io_are_fixtures': True})
    except Exception as exc:
        report['error'] = str(exc)
        raise
    finally:
        (output/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS' if report['passed'] else 'INCOMPATIBLE', ': actual old kernel reader vs actual binary records; NOT kernel execution')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
