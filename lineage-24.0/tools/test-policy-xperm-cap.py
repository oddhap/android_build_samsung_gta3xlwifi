#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exhaustive fixture test of the actual legacy kernel's new capability gate.

Tests the extracted production helper, not the entire loader or kernel. The
source callsite is checked too. No actual policy or enforcement is modified.
"""
import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('policydb', type=Path)
    p.add_argument('--cc', default='cc')
    args = p.parse_args()
    text = args.policydb.read_text()
    match = re.search(r'^static int policydb_check_legacy_xperms\(.*?^}', text, re.M | re.S)
    if not match:
        raise ValueError('Missing actual production capability gate')
    function = match.group()
    begin = text.index('int policydb_read(')
    body = text[begin:]
    read_caps = body.index('ebitmap_read(&p->policycaps, fp)')
    check = body.index('rc = policydb_check_legacy_xperms(p);')
    read_avtab = body.index('avtab_read(')
    assert read_caps < check < read_avtab
    assert re.match(r'rc = policydb_check_legacy_xperms\(p\);\s+if \(rc\)\s+goto bad;', body[check:])
    source = r'''
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
struct ebitmap { uint64_t bits; };
struct policydb { struct ebitmap policycaps; };
#define KERN_ERR ""
static int printk(const char *s,...) { (void)s;return 0; }
static int ebitmap_get_bit(struct ebitmap *b,unsigned n) { return (b->bits >> n) & 1; }
''' + function + r'''
int main(void) {
 unsigned tests=0;
 for(uint64_t bits=0;bits<(1U<<13);++bits) {
  struct policydb p={{bits}};
  int expected=(bits&(1U<<9)) ? -EOPNOTSUPP : 0;
  if(policydb_check_legacy_xperms(&p)!=expected)return 1;
  ++tests;
 }
 printf("PASS: %u capability combinations; actual helper, fixture bitmap, NOT kernel execution\n",tests);
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='legacy-policy-cap-') as d:
        c, exe = Path(d)/'gate.c', Path(d)/'gate'
        c.write_text(source)
        subprocess.run([args.cc, '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(c), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    print('Production policydb.c SHA-256:', hashlib.sha256(args.policydb.read_bytes()).hexdigest())


if __name__ == '__main__':
    main()
