#!/usr/bin/env python3
"""Actual socket classifier/create/label/bind bodies with fixture LSM backends.

Checks the supported legacy UAPI, exact cap-off behavior and modern classification
on that UAPI (preserving legacy DCCP; MPTCP/new families unavailable). Not live
socket execution, SCTP support, complete networking or hardware validation.
"""
import argparse,hashlib,importlib.util,json,re,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ['kernel','before','modern','constants','report']:p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();assert not a.report.exists()
def module(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
func=module('extract','test-netlink-xperm24.py').function;table=module('surface','audit-kernel-policy-surface.py').table
rel='security/selinux/';old=table(a.before/(rel+'include/classmap.h'),'clang');new=table(a.kernel/(rel+'include/classmap.h'),'clang');modern=table(a.modern/(rel+'include/classmap.h'),'clang')
assert list(new)[:len(old)]==list(old)
for name in old:assert old[name]==new[name]
added=list(new)[len(old):];assert len(added)==26
for name in added:assert new[name]==modern[name]
common=new['socket']
for name in added:assert new[name][:len(common)]==common
for name in ['rawip_socket','icmp_socket','sctp_socket']:assert new[name].index('node_bind')==len(common)
constants=json.loads(a.constants.read_text())['constants'];defs=[]
for k,v in constants.items():
 if k.isidentifier():defs.append(f'#define {k} {v}')
for i,(name,perms) in enumerate(new.items(),1):
 defs.append(f'#define SECCLASS_{name.upper()} {i}')
 for j,perm in enumerate(perms):defs.append(f'#define {name.upper()}__{perm.upper()} (1U<<{j})')
head=(a.kernel/(rel+'include/security.h')).read_text();caps=head[head.index('/* Policy capabilities */'):head.index('extern int selinux_android_netlink_route;')]
fs=(a.kernel/(rel+'selinuxfs.c')).read_text();names=re.search(r'static char \*policycap_names\[\] = \{.*?\n};',fs,re.S)[0]
source=(a.kernel/(rel+'hooks.c')).read_text();before=(a.before/(rel+'hooks.c')).read_text();reference=(a.modern/(rel+'hooks.c')).read_text()
parts=[r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;typedef uint16_t u16;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define max(a,b) ((a)>(b)?(a):(b))
#define SECSID_NULL 0
''','\n'.join(defs),caps,names,r'''
int selinux_policycap_extsockclass,selinux_policycap_netpeer,selinux_policycap_openperm;
int selinux_policycap_alwaysnetwork,selinux_policycap_nnp_nosuid_transition;
int selinux_policycap_functionfs_seclabel,selinux_policycap_netlink_xperm,selinux_android_netlink_route;
static struct {u32 policycaps;int android_netlink_route;} policydb;
static int ebitmap_get_bit(u32 *bits,unsigned bit) {assert(bit<32);return (*bits>>bit)&1;}
static bool fixture_extsockclass(void) {return selinux_policycap_extsockclass;}
''']
for fn in ['default_protocol_stream','default_protocol_dgram']:parts.append(func(source,fn))
for prefix,text in [('legacy',before),('candidate',source),('reference',reference)]:
 body=func(text,'socket_type_to_security_class').replace('socket_type_to_security_class(',prefix+'_class(',1)
 if prefix=='reference':
  body=body.replace('selinux_policycap_extsockclass()','fixture_extsockclass()')
  for family,returned in re.findall(r'\t\tcase (PF_\w+):\n\t\t\treturn (SECCLASS_\w+);\n',body):
   if family not in constants:body=body.replace(f'\t\tcase {family}:\n\t\t\treturn {returned};\n','')
 parts.append(body)
parts.append(func((a.kernel/(rel+'ss/services.c')).read_text(),'security_load_policycaps'))
parts.append(r'''
#define socket_type_to_security_class candidate_class
#define LSM_AUDIT_DATA_NET 1
struct task_security_struct {u32 sid,sockcreate_sid;};
static struct task_security_struct tasksec={42,0};
static const struct task_security_struct *current_security(void) {return &tasksec;}
struct task_struct {int unused;};static struct task_struct actor;
#define current (&actor)
static u32 task_sid(struct task_struct *task) {assert(task==current);return 42;}
struct inode_security_struct {u16 sclass;u32 sid;int initialized;};
struct inode {struct inode_security_struct *i_security;};
struct sk_security_struct {u32 sid;u16 sclass;};
struct sock {struct sk_security_struct *sk_security;u16 sk_family;int sk_protocol;};
struct socket {struct sock *sk;struct inode *inode;};
#define SOCK_INODE(s) ((s)->inode)
struct in6_addr {unsigned char s6_addr[16];};
struct sockaddr {u16 sa_family;};
struct sockaddr_in {u16 sin_family,sin_port;struct {u32 s_addr;} sin_addr;unsigned char padding[8];};
struct sockaddr_in6 {u16 sin6_family,sin6_port;u32 flow;struct in6_addr sin6_addr;u32 scope;};
struct lsm_network_audit {struct sock *sk;u16 sport,family;struct {u32 saddr;} v4info;struct {struct in6_addr saddr;} v6info;};
struct common_audit_data {int type;union {struct lsm_network_audit *net;} u;};
static u16 htons(u16 n) {return (n>>8)|(n<<8);}
#define ntohs htons
static unsigned calls,fail_call;static int injected_error,transition_error,netlabel_error;
static u16 expected_class;static u32 expected_node_perm;
static int security_transition_sid(u32 s,u32 t,u16 c,void *name,u32 *sid) {
 assert(s==42 && t==42 && c==expected_class && name==NULL);*sid=84;return transition_error;
}
static int avc_has_perm(u32 s,u32 t,u16 c,u32 perms,struct common_audit_data *ad) {
 assert(c==expected_class);calls++;
 if(!ad) {assert(s==42 && (t==84 || t==123) && perms==SOCKET__CREATE);}
 else {
  assert(ad->type==LSM_AUDIT_DATA_NET);
  if(t==84 || t==123)assert(s==42 && perms==SOCKET__BIND);
  else if(t==100)assert(s==84 && perms==SOCKET__NAME_BIND);
  else {assert(t==200 && s==84 && perms==expected_node_perm);}
 }
 return calls==fail_call ? injected_error:0;
}
static int selinux_netlbl_socket_post_create(struct sock *sk,int family) {
 assert(sk->sk_security->sclass==expected_class && sk->sk_family==family);return netlabel_error;
}
static int fixture_net;
static int *sock_net(struct sock *sk) {(void)sk;return &fixture_net;}
static void inet_get_local_port_range(int *net,int *low,int *high) {assert(net==&fixture_net);*low=32768;*high=60999;}
static int sel_netport_sid(int proto,u16 port,u32 *sid) {(void)proto;assert(port==443);*sid=100;return 0;}
static int sel_netnode_sid(char *addr,u16 family,u32 *sid) {assert(addr && (family==PF_INET||family==PF_INET6));*sid=200;return 0;}
''')
for fn in ['socket_sockcreate_sid','sock_has_perm','selinux_socket_create','selinux_socket_post_create','selinux_socket_bind']:parts.append(func(source,fn))
parts.append(r'''
int main(void) {
 unsigned long classified=0,capabilities=0,hooks=0;
 assert(strcmp(policycap_names[2],"extended_socket_class")==0);
 assert(strcmp(policycap_names[5],"nnp_nosuid_transition")==0 && !policycap_names[4]);
 assert(strcmp(policycap_names[12],"functionfs_seclabel")==0);
 for(unsigned bits=0;bits<(1<<13);bits++)for(unsigned route=0;route<2;route++) {
  policydb.policycaps=bits;policydb.android_netlink_route=route;security_load_policycaps();
  assert(selinux_policycap_extsockclass==((bits>>2)&1));
  assert(selinux_policycap_netpeer==(bits&1) && selinux_policycap_openperm==((bits>>1)&1));
  assert(selinux_policycap_alwaysnetwork==((bits>>3)&1));
  assert(selinux_policycap_nnp_nosuid_transition==((bits>>5)&1));
  assert(selinux_policycap_netlink_xperm==((bits>>9)&1));
  assert(selinux_policycap_functionfs_seclabel==((bits>>12)&1) && selinux_android_netlink_route==(int)route);capabilities++;
 }
 for(unsigned cap=0;cap<2;cap++)for(int family=-1;family<=PF_MAX+1;family++)
 for(int type=0;type<16;type++)for(int protocol=0;protocol<256;protocol++) {
  selinux_policycap_extsockclass=cap;u16 actual=candidate_class(family,type,protocol),expected;
  if(!cap)expected=legacy_class(family,type,protocol);
  else if((family==PF_INET||family==PF_INET6)&&type==SOCK_DCCP)expected=SECCLASS_DCCP_SOCKET;
  else expected=reference_class(family,type,protocol);
  assert(actual==expected);classified++;
 }
 for(unsigned cap=0;cap<2;cap++)for(unsigned which=0;which<3;which++)
 for(unsigned preset=0;preset<2;preset++)for(unsigned kern=0;kern<2;kern++)
 for(unsigned fail=0;fail<3;fail++) {
  const int families[]={PF_INET,PF_INET6,PF_PHONET};int family=families[which];
  selinux_policycap_extsockclass=cap;expected_class=candidate_class(family,SOCK_DGRAM,IPPROTO_ICMP);
  tasksec.sockcreate_sid=preset?123:0;transition_error=fail==1?-ENOMEM:0;
  fail_call=fail==2?1:0;injected_error=-EACCES;calls=0;
  int rc=selinux_socket_create(family,SOCK_DGRAM,IPPROTO_ICMP,kern);
  int transition_failed=!kern&&!preset&&transition_error;
  assert(rc==(kern?0:transition_failed?-ENOMEM:fail==2?-EACCES:0));
  assert(calls==(unsigned)(!kern&&!transition_failed));
  struct sk_security_struct sksec={0,0};struct sock sk={&sksec,family,IPPROTO_ICMP};
  struct inode_security_struct isec={0,0,0};struct inode inode={&isec};struct socket sock={&sk,&inode};
  netlabel_error=fail==2?-EACCES:0;
  rc=selinux_socket_post_create(&sock,family,SOCK_DGRAM,IPPROTO_ICMP,kern);
  assert(rc==(transition_failed?-ENOMEM:netlabel_error));
  if(!transition_failed)assert(isec.initialized && sksec.sclass==expected_class && sksec.sid==(kern?SECINITSID_KERNEL:preset?123:84));
  hooks+=2;
 }
 tasksec.sockcreate_sid=0;transition_error=netlabel_error=0;
 for(unsigned cap=0;cap<2;cap++)for(unsigned which=0;which<3;which++)
 for(unsigned port=0;port<3;port++)for(unsigned fail=0;fail<4;fail++) {
  const int families[]={PF_INET,PF_INET6,PF_PHONET};const unsigned ports[]={0,50000,443};int family=families[which];
  selinux_policycap_extsockclass=cap;expected_class=candidate_class(family,SOCK_DGRAM,IPPROTO_ICMP);
  expected_node_perm=cap?ICMP_SOCKET__NODE_BIND:RAWIP_SOCKET__NODE_BIND;
  struct sk_security_struct sksec={84,expected_class};struct sock sk={&sksec,family,IPPROTO_ICMP};
  struct socket sock={&sk,NULL};struct sockaddr_in v4={0};struct sockaddr_in6 v6={0};
  v4.sin_port=v6.sin6_port=htons(ports[port]);calls=0;fail_call=fail;injected_error=-EACCES;
  unsigned total=which==2?1:port==2?3:2;
  int rc=selinux_socket_bind(&sock,which==1?(struct sockaddr*)&v6:(struct sockaddr*)&v4,which==1?sizeof(v6):sizeof(v4));
  assert(rc==(fail&&fail<=total?-EACCES:0) && calls==(fail&&fail<=total?fail:total));hooks++;
 }
 printf("PASS: %lu classifier, %lu capability-loading, %lu create/label/bind fixture scenarios; 26 appended classes\n",classified,capabilities,hooks);
 return 0;
}
''')
text='\n'.join(parts)
text=text.replace('int main(void) {',f'_Static_assert(sizeof(struct sockaddr_in)=={constants["sizeof(struct sockaddr_in)"]},"target IPv4 layout");\n_Static_assert(sizeof(struct sockaddr_in6)=={constants["sizeof(struct sockaddr_in6)"]},"target IPv6 layout");\nint main(void) {{',1)
with tempfile.TemporaryDirectory(prefix='extsock-') as d:
 t=Path(d);(t/'test.c').write_text(text)
 command=['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=address,undefined',str(t/'test.c'),'-o',str(t/'test')]
 subprocess.run(command,check=True);result=subprocess.run([str(t/'test')],check=True,text=True,capture_output=True);print(result.stdout,end='')
 guard=subprocess.run(command+['-DCONFIG_IP_SCTP=1'],capture_output=True,text=True)
 assert guard.returncode and 'SCTP association and bind/connect LSM hooks are not backported' in guard.stderr
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files=[a.kernel/(rel+x) for x in ['hooks.c','include/classmap.h','include/security.h','ss/services.c','selinuxfs.c']]+[a.before/(rel+'hooks.c'),a.before/(rel+'include/classmap.h'),a.modern/(rel+'hooks.c'),a.modern/(rel+'include/classmap.h'),a.constants]
a.report.write_text(json.dumps({'passed':True,'scope':__doc__,'result':result.stdout.strip(),'appended_classes':added,'existing_class_and_permission_ids_unchanged':True,'SCTP_enabled_build_rejected':True,'inputs_sha256':{str(f):sha(f) for f in files},'runner_sha256':sha(Path(__file__)),'hardware_tested':False,'complete_socket_or_network_enforcement_validated':False},indent=2)+'\n')
