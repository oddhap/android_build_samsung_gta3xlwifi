#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual parsed-policy/SID/mapping/services/AVC/netlink bodies vs Android17 libsepol.

Memory, locks, task/socket/skb metadata, single-entry cache and audit backends are
sequential host fixtures. Input policy and strict compiler provenance are hashed
separately. Not kernel boot, live reload, native cache or ABI proof.
"""
import argparse,hashlib,importlib.util,itertools,json,os,re,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['kernel','kernel-out','android-top','policy','constants','output']:p.add_argument('--'+n,type=Path,required=True)
p.add_argument('--strict-report',type=Path,help='Successful strict compiler report bound to this exact policy')
a=p.parse_args()
strict_provenance=None
if a.strict_report:
 a.strict_report=a.strict_report.resolve();strict_provenance=json.loads(a.strict_report.read_text())
 assert strict_provenance['passed_strict']
 entries=[x for x in strict_provenance['results'] if x['mode']=='strict'];assert len(entries)==1
 entry=entries[0];assert entry['exit_code']==0 and entry['neverallow_checks_enabled'] and '-N' not in entry['command']
 assert hashlib.sha256(a.policy.read_bytes()).hexdigest()==entry['compiled_policy_sha256']
 assert str(a.policy.resolve())==str(Path(entry['command'][entry['command'].index('-o')+1]).resolve())
 for item in strict_provenance['inputs']:assert hashlib.sha256(Path(item['path']).read_bytes()).hexdigest()==item['sha256']
for n in ['kernel','kernel_out','android_top','policy','constants','output']:setattr(a,n,getattr(a,n).resolve())
for protected in [a.kernel,a.kernel_out,a.android_top,a.policy.parent]:assert not a.output.is_relative_to(protected)
assert not a.output.exists();a.output.mkdir()
out=a.output;root=Path(__file__).resolve().parent;fixture=root/'fixtures/netlink-policy24';compat=root/'fixtures/policydb-host24/compat'
(out/'NOT_READY_FOR_FLASHING.txt').write_text('Host regression only; strict compiler status is recorded separately. No boot validation or prebuilt promotion.\n')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
spec=importlib.util.spec_from_file_location('extract',root/'test-netlink-xperm24.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ss=a.kernel/'security/selinux/ss';sv=(ss/'services.c').read_text();mls=(ss/'mls.c').read_text()
read=m.function((ss/'policydb.c').read_text(),'policydb_read');assert read.index('ebitmap_read(&p->policycaps, fp)')<read.index('policydb_check_legacy_caps(p)')<read.index('avtab_read(')
cmdfile=a.kernel_out/'security/selinux/ss/.policydb.o.cmd';cmd=cmdfile.read_text();assert '-fno-strict-overflow' in cmd and not re.search(r'-D\s*CONFIG_ALWAYS_ENFORCE(?:\s|=|$)',cmd)
header='''#include <bridge.h>
#include "security.h"
#include "policydb.h"
#include "mls.h"
#include "conditional.h"
#include "avc_ss.h"
#include "classmap.h"
struct policydb policydb;
static struct sidtab sidtab;
static int policy_rwlock;
int ss_initialized;
static u32 latest_granting;
static unsigned reload_after_unlocked;
void host_unlock_hook(void){if(reload_after_unlocked && --reload_after_unlocked==0)latest_granting++;}
int selinux_policycap_netlink_xperm,selinux_policycap_netpeer,selinux_policycap_openperm,selinux_policycap_extsockclass,selinux_policycap_nnp_nosuid_transition,selinux_policycap_functionfs_seclabel;
'''
actual=(a.kernel/'security/selinux/include/avc.h').read_text()
for n in ['AVC_EXT_IOCTL','AVC_EXT_NLMSG']:
 header+=re.search(r'^#define '+n+r' .*$',actual,re.M)[0]+'\n'
header+=re.search(r'struct selinux_mapping \{.*?\n};',sv,re.S)[0]+'\nstatic struct selinux_mapping *current_mapping;\nstatic u16 current_mapping_size;\n'
header+='''static void context_struct_compute_av(struct context *,struct context *,u16,struct av_decision *,struct extended_perms *);
static unsigned bounds_audits;
static void security_dump_masked_av(struct context *s,struct context *t,u16 c,u32 p,const char *reason){(void)s;(void)t;(void)c;(void)p;(void)reason;bounds_audits++;}
'''
header+=m.function((ss/'policydb.c').read_text(),'policydb_check_legacy_caps')+'\n'
fns=[m.function(mls,n) for n in ['mls_level_isvalid','mls_range_isvalid','mls_context_isvalid']]
fns +=[m.function(sv,n) for n in ['selinux_set_mapping','unmap_class','map_class','map_decision','constraint_expr_eval','type_attribute_bounds_av','services_compute_xperms_drivers','context_struct_compute_av','avd_init','update_xperms_extended_data','services_compute_xperms_decision','security_compute_xperms_decision','security_compute_av']]
avc=(a.kernel/'security/selinux/avc.c').read_text()
backend=(fixture/'avc-backend.c').read_text()
structs='\n'.join(re.search(r'struct '+n+r' \{.*?\n};',avc,re.S)[0] for n in ['avc_entry','avc_node','avc_xperms_decision_node','avc_xperms_node'])
backend=backend.replace('/* ACTUAL_AVC_STRUCTS */',structs)
for n in ['AVC_STRICT','AVC_EXTENDED_PERMS','AVC_CALLBACK_GRANT','AVC_CALLBACK_ADD_XPERMS']:
 header+=re.search(r'^#define '+n+r'\s+.*$',actual,re.M)[0]+'\n'
body='\n\n'.join(m.function(avc,n) for n in ['avc_xperms_decision_lookup','avc_xperms_has_perm','avc_quick_copy_xperms_decision','avc_xperms_audit_required','avc_xperms_audit','avc_compute_av','avc_denied','avc_has_extended_perms_gen','avc_has_extended_perms_seqno'])
import json
constants=json.loads(a.constants.read_text())['constants']
packet=(fixture/'packet-backend.c').read_text()
obj=(a.kernel/'security/selinux/include/objsec.h').read_text()
packet=packet.replace('/* ACTUAL_SOCKET_SECURITY_STRUCT */',re.search(r'struct sk_security_struct \{.*?\n};',obj,re.S)[0])
look=(a.kernel/'security/selinux/nlmsgtab.c').read_text()
look='\n'.join(x for x in look.splitlines() if not x.startswith('#include'))
packet='#include "av_permissions.h"\n'+'\n'.join(f'#define {k} {v}U' for k,v in constants.items() if k.isidentifier() and not k.startswith(('SECCLASS_','SECINITSID_','NETLINK_')))+'\n'+packet+'\n'+look
packet+='\n'.join(m.function(sv,n) for n in ['security_load_policycaps','security_netlink_state','security_netlink_state_valid'])
packet+='\n'.join(m.function(actual,n) for n in ['avc_audit_required','avc_audit'])
packet+='\n'.join(m.function(avc,n) for n in ['avc_has_perm_noaudit_gen','avc_has_perm_seqno'])
hooks=(a.kernel/'security/selinux/hooks.c').read_text()
packet+='\n'.join(m.function(hooks,n) for n in ['nlmsg_sock_has_perm','nlmsg_sock_has_extended_perms','selinux_nlmsg_perm','selinux_netlink_send'])
(out/'main.c').write_text(header+'\n\n'.join(fns)+'\n'+backend+'\n'+body+'\n'+packet+'\n'+(fixture/'driver.c').read_text())
source=[ss/(n+'.c') for n in ['policydb','avtab','ebitmap','hashtab','symtab','conditional','sidtab']]
flags=['-fuse-ld=lld','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-sign-compare','-Wno-unused-function','-Wno-missing-field-initializers','-fno-strict-overflow','-fno-strict-aliasing','-ffunction-sections','-fdata-sections','-fsanitize=address,undefined']
command=['clang',*flags,'-include',str(fixture/'bridge.h'),'-I'+str(fixture),'-I'+str(compat),'-I'+str(ss),'-I'+str(a.kernel/'security/selinux/include'),'-I'+str(a.kernel_out/'security/selinux'),str(out/'main.c'),*[str(x) for x in source],'-Wl,--gc-sections','-o',str(out/'kernel-probe')]
r=subprocess.run(command,capture_output=True,text=True);(out/'compile-kernel.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
lib=a.android_top/'out/soong/.intermediates/external/selinux/libsepol/libsepol/linux_glibc_x86_64_static/libsepol.a';cc=a.android_top/'prebuilts/clang/host/linux-x86/clang-r584948/bin/clang'
oracle_command=[str(cc),'-fuse-ld=lld','-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-Wno-missing-field-initializers','-I'+str(a.android_top/'external/selinux/libsepol/include'),'-I'+str(a.kernel/'security/selinux/include'),str(fixture/'oracle.c'),str(lib),'-o',str(out/'oracle')]
r=subprocess.run(oracle_command,capture_output=True,text=True);(out/'compile-oracle.log').write_text(r.stdout+r.stderr);assert r.returncode==0,r.stderr
names=['netd','system_server','untrusted_app','isolated_app','init','vold','mediaprovider','shell'];classes=['netlink_route_socket','netlink_tcpdiag_socket','netlink_audit_socket','netlink_xfrm_socket'];rows=[]
for i,(sn,tn,cl,cats,base,driver) in enumerate(itertools.product(names,names,classes,[(0,0),(1,0),(0,2),(1,2)],[1,2],[0,1,0x89,255])):rows.append(f'{i} {sn} {tn} {cl} {cats[0]} {cats[1]} {base} {driver}')
queries=out/'queries.tsv';queries.write_text('\n'.join(rows)+'\n');start=time.monotonic()
for name,exe in [('kernel',out/'kernel-probe'),('oracle',out/'oracle')]:
 with (out/(name+'.tsv')).open('w') as stdout,(out/(name+'.log')).open('w') as stderr:
  result=subprocess.run([str(exe),str(a.policy),str(queries)],stdout=stdout,stderr=stderr,env=dict(os.environ,UBSAN_OPTIONS='halt_on_error=1'))
 print(name,'exit',result.returncode,'elapsed',round(time.monotonic()-start,2),flush=True);assert result.returncode==0,name
actual=(out/'kernel.tsv').read_text().splitlines();expected=(out/'oracle.tsv').read_text().splitlines();assert len(actual)==len(expected)==len(rows)
diff=[{'query':rows[i],'kernel':x,'oracle':y} for i,(x,y) in enumerate(zip(actual,expected)) if x!=y]
(out/'differences.json').write_text(json.dumps(diff,indent=2)+'\n');assert not diff,diff[:2]
log=(out/'kernel.log').read_text();caps=re.search(r'CAPABILITIES: accepted=(\d+) rejected=(\d+) sparse_rejected=(\d+)',log);assert caps
counts=re.search(r'COUNTS: avc=(\d+) packet=(\d+) compound=(\d+) malformed=(\d+) null_security=(\d+) reload=(\d+) allow=(\d+) deny=(\d+)',log);assert counts
counts=dict(zip(['avc','packet','compound','malformed','null_security','reload','allow','deny'],map(int,counts.groups())))
assert counts['avc']==len(rows)*256*3 and counts['packet']==len(rows)//2*256*3
inputs=[*source,*sorted(ss.glob('*.h')),ss/'services.c',ss/'mls.c',a.kernel/'security/selinux/avc.c',a.kernel/'security/selinux/nlmsgtab.c',a.kernel/'security/selinux/hooks.c',*[a.kernel/'security/selinux/include'/n for n in ['security.h','conditional.h','classmap.h','avc.h','avc_ss.h','objsec.h']],*[a.kernel_out/'security/selinux'/n for n in ['flask.h','av_permissions.h']],a.kernel_out/'.config',cmdfile,a.policy,a.constants,lib,cc,root/'test-netlink-xperm24.py',Path(__file__),*sorted(x for x in fixture.rglob('*') if x.is_file()),*sorted(x for x in compat.rglob('*') if x.is_file())]
if a.strict_report:inputs.append(a.strict_report)
report={'passed':True,'scope':__doc__,'unmodified_input_policydb_read_passed':True,'actual_capability_loader_used':True,'guard_combinations':16384,'guard_accepted':int(caps[1]),'guard_rejected':int(caps[2]),'sparse_unknown_bits_rejected':int(caps[3]),'query_count':len(rows),'counts':counts,'independent_oracle_differences':len(diff),'policy_sha256':sha(a.policy),'inputs_sha256':{str(x):sha(x) for x in inputs},'outputs_sha256':{x.name:sha(x) for x in out.iterdir() if x.is_file()},'kernel_compile_command':command,'oracle_compile_command':oracle_command,'whole_kernel_policy_load_proven':False,'native_cache_or_live_reload_validated':False,'strict_policy_passed':strict_provenance is not None,'strict_report':str(a.strict_report) if a.strict_report else None,'hardware_tested':False,'flash_ready':False}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: real decoded policy and capabilities, SID/mapping/services/AVC/skb bodies match independent Android17 libsepol; not boot/enforcement approval')
