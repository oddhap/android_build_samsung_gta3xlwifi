#!/usr/bin/env python3
"""Sanitized host checks of extracted kernel helper bodies, not kernel execution.

Compile the candidate, immutable Android17 reference and pre-candidate legacy
helpers together. No active Android source, Image or policycap guard is changed.
"""
import hashlib
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

FILES = ['security/selinux/ss/services.c', 'security/selinux/avc.c',
         'security/selinux/include/security.h', 'security/selinux/ss/avtab.h']


def function(s, name):
    m = re.search(r'^(?:static )?(?:inline )?(?:noinline )?[\w\s*]+\b' +
                  re.escape(name) + r'\([^;]*?\)\s*\{', s, re.M)
    assert m, name
    clean = re.sub(r'/\*.*?\*/|//[^\n]*', lambda m: ' ' * len(m[0]), s, flags=re.S)
    i = clean.index('{', m.start()) + 1
    depth = 1
    while depth:
        depth += (clean[i] == '{') - (clean[i] == '}')
        i += 1
    return s[m.start():i]


def generation_harness(source, snapshot=False):
    """Inject reload generations into the existing sequential AVC fixture."""
    changes = [
        ('static int fixture_cache_hit,',
         'static u32 fixture_generation=9;\nstatic unsigned fixture_adds,fixture_audits;\nstatic int fixture_cache_hit,'),
        ('struct extended_perms_decision *d) {\n assert(s==10',
         'struct extended_perms_decision *d,u32 *seqno) {\n *seqno=fixture_generation;\n assert(s==10'),
        ('else { assert(event==AVC_CALLBACK_ADD_XPERMS && d!=NULL && flags==0); }',
         'else { assert(event==AVC_CALLBACK_ADD_XPERMS && d!=NULL && flags==0); fixture_adds++; }'),
        ('(void)xp; (void)rc;', '(void)xp; (void)rc; fixture_audits++;'),
        ('unsigned long avc_cases=0;', 'unsigned long avc_cases=0,generation_cases=0;'),
        ('        if((command&255)==0) {', r'''
        if(cached!=2 && (command==0 || command==255 || command==256 ||
                         command==32768 || command==65535)) {
            const u32 generations[]={0,8,10,0xffffffffU};
            for(unsigned g=0;g<ARRAY_SIZE(generations);g++)
            for(unsigned enforcing=0;enforcing<2;enforcing++)
            for(unsigned permissive=0;permissive<2;permissive++) {
                fixture_generation=generations[g];
                selinux_enforcing=enforcing;
                fixture_node.ae.avd.flags=permissive ? AVD_FLAGS_PERMISSIVE:0;
                fixture_adds=fixture_audits=fixture_grants=0;
                rc=avc_has_extended_perms(10,20,42,1,fixture_driver,base,fixture_perm,NULL);
                assert(rc==-EAGAIN && rcu_depth==0);
                assert(fixture_adds==0 && fixture_audits==0 && fixture_grants==0);
                generation_cases++;
            }
            fixture_generation=9;selinux_enforcing=1;fixture_node.ae.avd.flags=0;
        }
        if((command&255)==0) {'''),
        ('    printf("PASS: %lu helper',
         '    printf("PASS: %lu generation mismatch scenarios; ",generation_cases);\n    printf("PASS: %lu helper'),
    ]
    for old, new in changes:
        assert source.count(old) == 1, old
        source = source.replace(old, new, 1)
    if snapshot:
        marker = '        if((command&255)==0) {'
        checks = r'''
        if(command==0 || command==255 || command==256 || command==32768 || command==65535) {
            const u32 expected_generations[]={0,8,10,0xffffffffU};
            for(unsigned g=0;g<ARRAY_SIZE(expected_generations);g++)
            for(unsigned enforcing=0;enforcing<2;enforcing++)
            for(unsigned permissive=0;permissive<2;permissive++) {
                selinux_enforcing=enforcing;
                fixture_node.ae.avd.flags=permissive ? AVD_FLAGS_PERMISSIVE:0;
                fixture_adds=fixture_audits=fixture_grants=fixture_computes=0;
                rc=avc_has_extended_perms_seqno(10,20,42,1,fixture_driver,base,
                                               fixture_perm,NULL,expected_generations[g]);
                assert(rc==-EAGAIN && rcu_depth==0);
                assert(fixture_adds==0 && fixture_audits==0 && fixture_grants==0 && fixture_computes==0);
                rc=avc_has_perm_seqno(10,20,42,1,NULL,expected_generations[g]);
                assert(rc==-EAGAIN && rcu_depth==0);
                assert(fixture_adds==0 && fixture_audits==0 && fixture_grants==0);
                generation_cases+=2;
            }
            selinux_enforcing=1;fixture_node.ae.avd.flags=0;
            rc=avc_has_extended_perms_seqno(10,20,42,1,fixture_driver,base,fixture_perm,NULL,9);
            assert(rc==(allow ? 0:-EACCES) && rcu_depth==0);
            fixture_node.ae.avd.allowed=allow ? 1:0;
            rc=avc_has_perm_seqno(10,20,42,1,NULL,9);
            assert(rc==(allow ? 0:-EACCES) && rcu_depth==0);
            fixture_node.ae.avd.allowed=1;
            generation_cases+=2;
        }
'''
        assert source.count(marker) == 1
        source = source.replace(marker, checks + marker, 1)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--legacy', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--generation-bound', action='store_true',
                        help='Check the isolated xperm/AV generation-binding API and fail-closed mismatch path')
    parser.add_argument('--snapshot-bound', action='store_true',
                        help='Also check expected-generation base/extended AVC APIs, including existing cache hits')
    args = parser.parse_args()
    if args.snapshot_bound and not args.generation_bound:
        parser.error('--snapshot-bound requires --generation-bound')
    if args.report.exists():
        raise FileExistsError('Use a fresh report path')
    trees = [args.kernel, args.reference, args.legacy]
    sec = (trees[0] / FILES[2]).read_text()
    avtab = (trees[0] / FILES[3]).read_text()
    definitions = sec[sec.index('#define XPERMS_ALLOWED'):sec.index('struct extended_perms {')]
    definitions += sec[sec.index('struct extended_perms {'):sec.index('struct extended_perms {') +
                       sec[sec.index('struct extended_perms {'):].index('\n};') + 3]
    definitions += '\n' + avtab[avtab.index('struct avtab_key {'):avtab.index('struct avtab {')]
    # Samsung intentionally makes per-domain permissive flags ineffective in
    # ALWAYS_ENFORCE builds. Compile the actual conditional header definition.
    definitions += '\n' + sec[sec.index('/* definitions of av_decision.flags */'):
                               sec.index('void security_compute_av(')]
    parts = [r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define AVC_EXT_IOCTL 1
#define AVC_EXT_NLMSG 2
#define BUG() abort()
#define pr_warn_once(...) ((void)0)
int selinux_policycap_netlink_xperm;
''', definitions]
    for index, tree in enumerate(trees):
        source = (tree / FILES[0]).read_text()
        names = ['services_compute_xperms_drivers', 'services_compute_xperms_decision']
        if index != 2:
            names.insert(1, 'update_xperms_extended_data')
        for name in names:
            f = function(source, name)
            for symbol in names:
                f = re.sub(r'\b' + symbol + r'\b', f'{symbol}_{index}', f)
            parts.append(f)
    parts.append(r'''
/* Sequential list fixture: no RCU, concurrency or kernel allocator modeled. */
struct list_head { struct list_head *next,*prev; };
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) \
 for(p=container_of((h)->next,__typeof__(*p),m); &(p)->m!=(h); \
 p=container_of((p)->m.next,__typeof__(*p),m))
struct avc_xperms_decision_node {
 struct extended_perms_decision xpd; struct list_head xpd_list;
};
struct avc_xperms_node { struct extended_perms xp; struct list_head xpd_head; };
''')
    avc = (trees[0] / FILES[1]).read_text()
    if args.generation_bound:
        service = (trees[0] / FILES[0]).read_text()
        compute = function(service, 'security_compute_xperms_decision')
        assert compute.index('read_lock(&policy_rwlock)') < compute.index('*seqno = latest_granting;') < compute.index('if (!ss_initialized)')
        assert compute.index('*seqno = latest_granting;') < compute.index('read_unlock(&policy_rwlock)')
        load = function(service, 'security_load_policy')
        publish = load[load.index('/* Publish initial capabilities'):load.index('selinux_complete_init();')]
        ordered = ['write_lock_irq(&policy_rwlock)', 'security_load_policycaps()',
                   'ss_initialized = 1', 'seqno = ++latest_granting', 'write_unlock_irq(&policy_rwlock)']
        assert [publish.index(x) for x in ordered] == sorted(publish.index(x) for x in ordered)
        assert 'u32 *seqno' in compute
    for name in ['avc_xperms_has_perm', 'avc_copy_xperms_decision',
                 'avc_quick_copy_xperms_decision', 'avc_xperms_decision_lookup',
                 'avc_xperms_allow_perm']:
        parts.append(function(avc, name))
    parts.append(r'''
#include <errno.h>
#define unlikely(x) (x)
#define BUG_ON(x) assert(!(x))
#define noinline __attribute__((noinline))
#define AVC_STRICT 1
#define AVC_EXTENDED_PERMS 2
#define AVC_CALLBACK_GRANT 1
#define AVC_CALLBACK_ADD_XPERMS 2
struct av_decision { u32 allowed,auditallow,auditdeny,seqno,flags; };
struct common_audit_data { int fixture; };
struct avc_node { struct { struct av_decision avd; struct avc_xperms_node *xp_node; } ae; };
static struct avc_node fixture_node;
static struct avc_xperms_node fixture_xp;
static struct avc_xperms_decision_node fixture_cached;
static struct extended_perms_data fixture_data[3];
static int fixture_cache_hit,fixture_allowed,fixture_audit_error,fixture_grants,fixture_computes;
static unsigned fixture_driver,fixture_base,fixture_perm;
static int rcu_depth,selinux_enforcing=1;
static void rcu_read_lock(void) { assert(rcu_depth==0); rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth==1); rcu_depth--; }
static struct avc_node *avc_lookup(u32 s,u32 t,u16 c) {
 assert(s==10 && t==20 && c==42 && rcu_depth==1);
 return fixture_cache_hit ? &fixture_node:NULL;
}
static struct avc_node *avc_compute_av(u32 s,u32 t,u16 c,struct av_decision *d,
                                     struct avc_xperms_node *xp) {
 assert(s==10 && t==20 && c==42 && rcu_depth==1);
 *d=fixture_node.ae.avd; *xp=fixture_xp;
 /* The miss path has no separately cached xperm decisions. */
 xp->xpd_head.next=xp->xpd_head.prev=&xp->xpd_head;
 return NULL;
}
static int avc_update_node(u32 event,u32 requested,u8 driver,u8 base,u8 perm,
                          u32 s,u32 t,u16 c,u32 seq,struct extended_perms_decision *d,u32 flags) {
 assert(s==10 && t==20 && c==42 && requested==1 && seq==9);
 assert(driver==fixture_driver && base==fixture_base && perm==fixture_perm);
 assert(rcu_depth==1);
 if(event==AVC_CALLBACK_GRANT) { assert(flags==AVC_EXTENDED_PERMS && d==NULL); fixture_grants++; }
 else { assert(event==AVC_CALLBACK_ADD_XPERMS && d!=NULL && flags==0); }
 return 0;
}
static void security_compute_xperms_decision(u32 s,u32 t,u16 c,u8 driver,u8 base,
                                            struct extended_perms_decision *d) {
 assert(s==10 && t==20 && c==42 && rcu_depth==0);
 assert(driver==fixture_driver && base==fixture_base);
 d->driver=driver; d->base_perm=base; d->used=XPERMS_ALLOWED;
 memset(d->allowed,0,sizeof(*d->allowed));
 memset(d->auditallow,0,sizeof(*d->auditallow));
 memset(d->dontaudit,0,sizeof(*d->dontaudit));
 if(fixture_allowed) security_xperm_set(d->allowed->p,fixture_perm);
 fixture_computes++;
}
static int avc_xperms_audit(u32 s,u32 t,u16 c,u32 requested,struct av_decision *d,
                           struct extended_perms_decision *xp,u8 perm,int rc,
                           struct common_audit_data *ad) {
 assert(s==10 && t==20 && c==42 && requested==1 && d->seqno==9);
 assert(perm==fixture_perm && ad==NULL && rcu_depth==0);
 (void)xp; (void)rc;
 return fixture_audit_error;
}
''')
    parts.append(function(avc, 'avc_denied'))
    if args.snapshot_bound:
        parts.append(function(avc, 'avc_has_extended_perms_gen'))
        parts.append(function(avc, 'avc_has_extended_perms_seqno'))
        parts.append(function(avc, 'avc_has_perm_noaudit_gen'))
        parts.append(r'''
static int avc_audit(u32 s,u32 t,u16 c,u32 requested,struct av_decision *d,
                     int rc,struct common_audit_data *ad,int flags) {
 assert(flags==0);
 return avc_xperms_audit(s,t,c,requested,d,NULL,fixture_perm,rc,ad);
}
''')
        parts.append(function(avc, 'avc_has_perm_seqno'))
    parts.append(function(avc, 'avc_has_extended_perms'))
    parts.append(r'''
static void setup(struct extended_perms_decision *d, struct extended_perms_data *p,
                  unsigned driver, unsigned base) {
    memset(d, 0, sizeof(*d)); memset(p, 0, 3*sizeof(*p));
    d->allowed=p; d->auditallow=p+1; d->dontaudit=p+2;
    d->driver=driver; d->base_perm=base;
}
int main(void) {
    unsigned long cases=0;
    const u16 rules[]={AVTAB_XPERMS_ALLOWED,AVTAB_XPERMS_AUDITALLOW,AVTAB_XPERMS_DONTAUDIT};
    for(unsigned driver=0;driver<256;driver++)
    for(unsigned bit=0;bit<256;bit++)
    for(unsigned kind=1;kind<=3;kind++)
    for(unsigned rule=0;rule<3;rule++) {
        struct avtab_extended_perms xp={.specified=kind,.driver=driver};
        security_xperm_set(xp.perms.p,bit);
        struct avtab_node n={.key={.specified=rules[rule]},.datum={.u.xperms=&xp}};
        struct extended_perms c={0}, ref={0}, old={0};
        selinux_policycap_netlink_xperm=1;
        services_compute_xperms_drivers_0(&c,&n);
        services_compute_xperms_drivers_1(&ref,&n);
        assert(c.len==ref.len && c.base_perms==ref.base_perms);
        assert(!memcmp(&c.drivers,&ref.drivers,sizeof(c.drivers)));
        if(kind<3) {
            memset(&c,0,sizeof(c)); selinux_policycap_netlink_xperm=0;
            services_compute_xperms_drivers_0(&c,&n);
            services_compute_xperms_drivers_2(&old,&n);
            assert(c.len==old.len && !memcmp(&c.drivers,&old.drivers,sizeof(c.drivers)));
        }
        for(unsigned base=1;base<=2;base++)
        for(unsigned mismatch=0;mismatch<2;mismatch++)
        for(unsigned enabled=0;enabled<2;enabled++) {
            struct extended_perms_decision a,b,o,copy,quick;
            struct extended_perms_data ap[3],bp[3],op[3],cp[3],qp[3];
            unsigned qdriver=driver ^ mismatch;
            setup(&a,ap,qdriver,base); setup(&b,bp,qdriver,base);
            setup(&o,op,qdriver,base); setup(&copy,cp,0,0); setup(&quick,qp,0,0);
            n.key.specified=rules[rule] | (enabled ? AVTAB_ENABLED : 0);
            services_compute_xperms_decision_0(&a,&n);
            services_compute_xperms_decision_1(&b,&n);
            assert(a.used==b.used && !memcmp(ap,bp,sizeof(ap)));
            if(kind<3 && base==AVC_EXT_IOCTL && !enabled) {
                services_compute_xperms_decision_2(&o,&n);
                assert(a.used==o.used && !memcmp(ap,op,sizeof(ap)));
            }
            /* Independent single-rule expectation, including wrong namespace. */
            int matches= kind==2 ? (base==1 && qdriver==bit) :
                        (base==(kind==3 ? 2u:1u) && qdriver==driver);
            assert(a.used==(matches ? 1u<<rule : 0u));
            for(unsigned r=0;r<3;r++) for(unsigned word=0;word<8;word++) {
                u32 expected=0;
                if(matches && r==rule) expected=kind==2 ? UINT32_MAX :
                    (word==bit/32 ? 1U<<(bit%32) : 0);
                assert(ap[r].p[word]==expected);
            }
            avc_copy_xperms_decision(&copy,&a);
            avc_quick_copy_xperms_decision(bit,&quick,&a);
            assert(copy.driver==qdriver && copy.base_perm==base && copy.used==a.used);
            assert(quick.driver==qdriver && quick.base_perm==base && quick.used==a.used);
            assert(!memcmp(cp,ap,sizeof(ap)));
            for(unsigned which=1;which<=4;which<<=1) {
                assert(avc_xperms_has_perm(&copy,bit,which)==
                       avc_xperms_has_perm(&a,bit,which));
                assert(avc_xperms_has_perm(&quick,bit,which)==
                       avc_xperms_has_perm(&a,bit,which));
            }
            cases++;
        }
    }
    /* Same driver in two namespaces must never share a cached decision. */
    for(unsigned driver=0;driver<256;driver++)
    for(unsigned bit=0;bit<256;bit++) {
        struct avc_xperms_node node={0};
        struct avc_xperms_decision_node a={0},b={0};
        struct extended_perms_data ap[3],bp[3];
        setup(&a.xpd,ap,driver,1); setup(&b.xpd,bp,driver,2);
        node.xpd_head.next=&a.xpd_list; node.xpd_head.prev=&b.xpd_list;
        a.xpd_list.prev=&node.xpd_head; a.xpd_list.next=&b.xpd_list;
        b.xpd_list.prev=&a.xpd_list; b.xpd_list.next=&node.xpd_head;
        assert(avc_xperms_decision_lookup(driver,1,&node)==&a.xpd);
        assert(avc_xperms_decision_lookup(driver,2,&node)==&b.xpd);
        assert(avc_xperms_decision_lookup(driver^1,1,&node)==NULL);
        assert(avc_xperms_decision_lookup(driver,0,&node)==NULL);
        avc_xperms_allow_perm(&node,driver,2,bit);
        assert(!security_xperm_test(ap[0].p,bit));
        assert(security_xperm_test(bp[0].p,bit));
        assert(node.xp.base_perms==2);
        avc_xperms_allow_perm(&node,driver,1,bit^1);
        assert(!security_xperm_test(bp[0].p,bit^1));
        assert(security_xperm_test(ap[0].p,bit^1));
        assert(node.xp.base_perms==3);
        cases++;
    }
    unsigned long avc_cases=0;
    for(unsigned command=0;command<65536;command++)
    for(unsigned base=1;base<=2;base++)
    for(unsigned cached=0;cached<3;cached++)
    for(unsigned allow=0;allow<2;allow++) {
        fixture_driver=command>>8; fixture_perm=command&255; fixture_base=base;
        fixture_cache_hit=cached!=0; fixture_allowed=allow;
        fixture_grants=fixture_computes=fixture_audit_error=0;
        memset(&fixture_node,0,sizeof(fixture_node));
        memset(&fixture_xp,0,sizeof(fixture_xp));
        memset(&fixture_cached,0,sizeof(fixture_cached));
        memset(fixture_data,0,sizeof(fixture_data));
        fixture_node.ae.avd.allowed=1; fixture_node.ae.avd.seqno=9;
        fixture_node.ae.xp_node=&fixture_xp;
        fixture_xp.xp.len=1; fixture_xp.xp.base_perms=base;
        security_xperm_set(fixture_xp.xp.drivers.p,fixture_driver);
        fixture_xp.xpd_head.next=fixture_xp.xpd_head.prev=&fixture_xp.xpd_head;
        if(cached==2) {
            fixture_cached.xpd.driver=fixture_driver; fixture_cached.xpd.base_perm=base;
            fixture_cached.xpd.used=XPERMS_ALLOWED; fixture_cached.xpd.allowed=fixture_data;
            if(allow) security_xperm_set(fixture_data[0].p,fixture_perm);
            fixture_xp.xpd_head.next=fixture_xp.xpd_head.prev=&fixture_cached.xpd_list;
            fixture_cached.xpd_list.next=fixture_cached.xpd_list.prev=&fixture_xp.xpd_head;
        }
        int rc=avc_has_extended_perms(10,20,42,1,fixture_driver,base,fixture_perm,NULL);
        assert(rc==(allow ? 0:-EACCES));
        assert(fixture_computes==(cached==2 ? 0:1) && fixture_grants==0 && rcu_depth==0);
        if((command&255)==0) {
            /* Exercise per-domain permissive and build-wide ALWAYS_ENFORCE. */
            for(unsigned enforcing=0;enforcing<2;enforcing++)
            for(unsigned permissive=0;permissive<2;permissive++) {
                selinux_enforcing=enforcing;
                fixture_node.ae.avd.flags=permissive ? AVD_FLAGS_PERMISSIVE:0;
                rc=avc_has_extended_perms(10,20,42,1,fixture_driver,base,fixture_perm,NULL);
                int domain_permissive=(fixture_node.ae.avd.flags & AVD_FLAGS_PERMISSIVE)!=0;
                int deny=!allow && !domain_permissive;
#ifndef CONFIG_ALWAYS_ENFORCE
                deny=deny && enforcing;
#endif
                assert(rc==(deny ? -EACCES:0) && rcu_depth==0);
                avc_cases++;
            }
            selinux_enforcing=1; fixture_node.ae.avd.flags=0;
            fixture_audit_error=-ENOMEM;
            rc=avc_has_extended_perms(10,20,42,1,fixture_driver,base,fixture_perm,NULL);
            assert(rc==-ENOMEM && rcu_depth==0);
            fixture_audit_error=0;
            /* Missing namespace/driver must deny even when base TE allows. */
            fixture_xp.xp.base_perms=0;
            fixture_xp.xpd_head.next=fixture_xp.xpd_head.prev=&fixture_xp.xpd_head;
            rc=avc_has_extended_perms(10,20,42,1,fixture_driver,base,fixture_perm,NULL);
            assert(rc==-EACCES && rcu_depth==0);
            fixture_xp.xp.base_perms=base; memset(&fixture_xp.xp.drivers,0,sizeof(fixture_xp.xp.drivers));
            rc=avc_has_extended_perms(10,20,42,1,fixture_driver,base,fixture_perm,NULL);
            assert(rc==-EACCES && rcu_depth==0);
            avc_cases+=3;
        }
        avc_cases++;
    }
    printf("PASS: %lu helper and %lu AVC fixture scenarios, references/cache isolation/enforcement/audit errors\n",cases,avc_cases);
    return 0;
}
''')
    with tempfile.TemporaryDirectory(prefix='netlink-xperm24-') as scratch:
        p = Path(scratch)
        harness = '\n'.join(parts)
        if args.generation_bound:
            harness = generation_harness(harness, args.snapshot_bound)
        (p / 'test.c').write_text(harness)
        results = []
        for config in [[], ['-DCONFIG_ALWAYS_ENFORCE']]:
            subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', *config, str(p/'test.c'), '-o', str(p/'test')], check=True)
            result = subprocess.run([str(p/'test')], check=True, text=True, capture_output=True)
            print(config, result.stdout, end='')
            results.append({'config':config, 'stdout':result.stdout.strip()})
        report = {'passed': True, 'scope': 'Extracted helpers with a sequential list fixture; not whole kernel or live enforcement',
                  'hardware_tested': False, 'policy_load_guard_removed': False,
                  'test_runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'AVD_FLAGS_PERMISSIVE_from_actual_conditional_header': True,
                  'generation_binding_fixture': args.generation_bound,
                  'expected_generation_AVC_fixture': args.snapshot_bound,
                  'whole_skb_and_reload_concurrency_validated': False,
                  'results': results, 'sanitizers': ['address', 'undefined'],
                  'inputs': {str(t/f):hashlib.sha256((t/f).read_bytes()).hexdigest()
                             for t in trees for f in FILES if (t/f).exists()}}
        dest = args.report
        dest.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
