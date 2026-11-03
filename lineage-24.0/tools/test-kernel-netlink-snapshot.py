#!/usr/bin/env python3
"""Actual netlink lookup, skb hook and snapshot bodies with sequential fixtures.

Packet/AVC/lock backends are fixtures. Separate actual AVC generation tests and
whole-kernel builds are required; this is not live reload or hardware evidence.
"""
import argparse,hashlib,importlib.util,json,re,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for key in ['kernel','before','constants','report']:p.add_argument('--'+key,type=Path,required=True)
a=p.parse_args();assert not a.report.exists()
spec=importlib.util.spec_from_file_location('extract',Path(__file__).with_name('test-netlink-xperm24.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
func=m.function;rel='security/selinux/'
constants=json.loads(a.constants.read_text())['constants']
head=(a.kernel/(rel+'include/security.h')).read_text();state=re.search(r'struct selinux_netlink_state \{.*?\n};',head,re.S)[0]
lookup=(a.kernel/(rel+'nlmsgtab.c')).read_text();oldlookup=(a.before/(rel+'nlmsgtab.c')).read_text()
assert 'selinux_nlmsg_init' not in lookup and lookup.count('static const struct nlmsg_perm ')==4
lookup='\n'.join(x for x in lookup.splitlines() if not x.startswith('#include'))
oldlookup='\n'.join(x for x in oldlookup.splitlines() if not x.startswith('#include'))
for name in ['nlmsg_perm','nlmsg_route_perms','nlmsg_tcpdiag_perms','nlmsg_xfrm_perms','nlmsg_audit_perms','selinux_nlmsg_lookup','nlmsg_set_getlink_perm','selinux_nlmsg_init']:
 oldlookup=re.sub(r'\b'+name+r'\b','legacy_'+name,oldlookup)
parts=[r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint32_t u32;typedef uint16_t u16;typedef uint8_t u8;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BUILD_BUG_ON(x) do { _Static_assert(!(x),"kernel bound"); } while(0)
''','\n'.join(f'#define {k} {v}U' for k,v in constants.items() if k.isidentifier()),state,r'''
struct nlmsghdr {u32 nlmsg_len;u16 nlmsg_type,nlmsg_flags;u32 nlmsg_seq,nlmsg_pid;};
#define NLMSG_ALIGN(x) (((x)+NLMSG_ALIGNTO-1)&~(NLMSG_ALIGNTO-1))
#define nlmsg_total_size(x) (NLMSG_ALIGN(NLMSG_HDRLEN+(x)))
int selinux_policycap_netlink_xperm,selinux_android_netlink_route,selinux_policycap_alwaysnetwork;
static int ss_initialized,policy_rwlock,lock_depth,unlocks,inject_snapshot;
static u32 latest_granting;
static struct {int allow_unknown;} policydb;
static void reload(void) {
 assert(lock_depth==0);latest_granting++;
 selinux_policycap_netlink_xperm^=1;selinux_android_netlink_route^=1;
 selinux_policycap_alwaysnetwork^=1;policydb.allow_unknown^=1;
}
static void read_lock(int *lock) {assert(lock==&policy_rwlock && lock_depth==0);lock_depth=1;}
static void read_unlock(int *lock) {assert(lock==&policy_rwlock && lock_depth==1);lock_depth=0;if(++unlocks==1 && inject_snapshot)reload();}
''',lookup,oldlookup]
services=(a.kernel/(rel+'ss/services.c')).read_text()
for fn in ['security_netlink_state','security_netlink_state_valid']:parts.append(func(services,fn))
parts.append(r'''
#define LSM_AUDIT_DATA_NET 7
#define LSM_AUDIT_DATA_NLMSGTYPE 8
#define AVC_EXT_NLMSG 2
struct sk_security_struct {u32 sid;u16 sclass;};
struct sock {struct sk_security_struct *sk_security;u16 sk_protocol;};
struct sk_buff {unsigned len;unsigned char *data;};
struct task_struct {char comm[8];};
static struct task_struct actor={"test"};
#define current (&actor)
struct lsm_network_audit {struct sock *sk;};
struct common_audit_data {int type;union {struct lsm_network_audit *net;u16 nlmsg_type;} u;};
static int selinux_enforcing;
#define pr_warn_ratelimited(...) ((void)0)
static u32 task_sid(struct task_struct *task) {assert(task==current);return 42;}
static u32 current_sid(void) {return 42;}
static unsigned callbacks,base_calls,ext_calls,inject_call;
static int callback_error;
static u32 seen_perms[4];static u16 seen_types[4];
static int callback(u32 s,u32 t,u16 c,u32 requested,u32 seq) {
 assert(!lock_depth && s==42 && (t==84 || t==SECINITSID_KERNEL) && c>0 && seq==9);
 assert(callbacks<4);seen_perms[callbacks]=requested;
 if(++callbacks==inject_call)reload();
 return callback_error;
}
static int avc_has_perm_seqno(u32 s,u32 t,u16 c,u32 requested,struct common_audit_data *ad,u32 seq) {
 assert(ad->type==LSM_AUDIT_DATA_NET && ad->u.net->sk->sk_security->sid==t);base_calls++;
 return callback(s,t,c,requested,seq);
}
static int avc_has_extended_perms_seqno(u32 s,u32 t,u16 c,u32 requested,u8 driver,u8 base,u8 perm,struct common_audit_data *ad,u32 seq) {
 assert(ad->type==LSM_AUDIT_DATA_NLMSGTYPE && base==AVC_EXT_NLMSG);
 assert(driver==(ad->u.nlmsg_type>>8) && perm==(ad->u.nlmsg_type&255));
 seen_types[callbacks]=ad->u.nlmsg_type;ext_calls++;
 return callback(s,t,c,requested,seq);
}
''')
hooks=(a.kernel/(rel+'hooks.c')).read_text()
for fn in ['nlmsg_sock_has_perm','nlmsg_sock_has_extended_perms','selinux_nlmsg_perm']:parts.append(func(hooks,fn))
parts.append(r'''
static void setup(unsigned x,unsigned route,unsigned always,unsigned unknown,unsigned enforcing) {
 ss_initialized=1;latest_granting=9;policydb.allow_unknown=unknown;
 selinux_policycap_netlink_xperm=x;selinux_android_netlink_route=route;selinux_policycap_alwaysnetwork=always;
 selinux_enforcing=enforcing;lock_depth=unlocks=inject_snapshot=0;
 callbacks=base_calls=ext_calls=inject_call=0;callback_error=0;
 legacy_selinux_nlmsg_init();
}
int main(void) {
 unsigned long lookups=0,packets=0,states=0;
 const u16 classes[]={SECCLASS_NETLINK_ROUTE_SOCKET,SECCLASS_NETLINK_TCPDIAG_SOCKET,
                     SECCLASS_NETLINK_XFRM_SOCKET,SECCLASS_NETLINK_AUDIT_SOCKET,SECCLASS_PACKET_SOCKET};
 for(unsigned x=0;x<2;x++)for(unsigned route=0;route<2;route++) {
  setup(x,route,0,0,1);struct selinux_netlink_state state;security_netlink_state(&state);
  for(unsigned c=0;c<ARRAY_SIZE(classes);c++)for(unsigned msg=0;msg<65536;msg++) {
   u32 before=0,after=0;int b=legacy_selinux_nlmsg_lookup(classes[c],msg,&before);
   int d=selinux_nlmsg_lookup(classes[c],msg,&after,&state);
   assert(b==d && (b!=0 || before==after));lookups++;
   /* Changing globals and the historical mutable table cannot alter a snapshot. */
   selinux_policycap_netlink_xperm^=1;selinux_android_netlink_route^=1;legacy_selinux_nlmsg_init();
   u32 stable=0;int e=selinux_nlmsg_lookup(classes[c],msg,&stable,&state);
   assert(e==d && (e!=0 || stable==after));
   selinux_policycap_netlink_xperm^=1;selinux_android_netlink_route^=1;legacy_selinux_nlmsg_init();lookups++;
  }
 }
 for(unsigned init=0;init<2;init++)for(unsigned x=0;x<2;x++)for(unsigned r=0;r<2;r++)
 for(unsigned always=0;always<2;always++)for(unsigned unknown=0;unknown<2;unknown++) {
  setup(x,r,always,unknown,1);ss_initialized=init;struct selinux_netlink_state state;
  security_netlink_state(&state);assert(state.seqno==9 && state.initialized==(int)init);
  assert(state.xperm==(int)(init&&x) && state.route==(int)(init&&r));
  assert(state.alwaysnetwork==(int)(init&&always) && state.allow_unknown==(int)(init&&unknown));
  assert(security_netlink_state_valid(&state));latest_granting++;assert(!security_netlink_state_valid(&state));
  latest_granting=9;ss_initialized^=1;assert(!security_netlink_state_valid(&state));states++;
 }
 const int errors[]={0,-EACCES,-ENOMEM};
 for(unsigned x=0;x<2;x++)for(unsigned route=0;route<2;route++)for(unsigned always=0;always<2;always++)
 for(unsigned unknown=0;unknown<2;unknown++)for(unsigned enforcing=0;enforcing<2;enforcing++)
 for(unsigned kernel=0;kernel<2;kernel++)for(unsigned c=0;c<ARRAY_SIZE(classes);c++)
 for(unsigned layout=0;layout<10;layout++)for(unsigned error=0;error<ARRAY_SIZE(errors);error++)
 for(unsigned injection=0;injection<4;injection++) {
  setup(x,route,always,unknown,enforcing);callback_error=errors[error];
  struct sk_security_struct sksec={kernel?SECINITSID_KERNEL:84,classes[c]};struct sock sk={&sksec,0};
  union {u32 align;unsigned char data[80];} buffer;memset(&buffer,0,sizeof(buffer));
  struct nlmsghdr first={16,RTM_GETLINK,0,0,0},second={16,0xffff,0,0,0};
  u16 messages[2]={first.nlmsg_type,second.nlmsg_type};unsigned count=0,len=0;
  switch(layout) {
   case 0:break;
   case 1:count=1;len=16;break;
   case 2:count=2;len=32;break;
   case 3:first.nlmsg_len=17;count=2;len=36;break;
   case 4:first.nlmsg_len=4;len=16;break;
   case 5:first.nlmsg_len=1000;len=16;break;
   case 6:count=1;len=19;break;
   case 7:second.nlmsg_len=4;count=1;len=32;break;
   case 8:len=3;break;
   case 9:first.nlmsg_type=0xffff;messages[0]=0xffff;count=1;len=16;break;
  }
  memcpy(buffer.data,&first,16);memcpy(buffer.data+NLMSG_ALIGN(first.nlmsg_len<80?first.nlmsg_len:16),&second,16);
  /* The deliberately short first header has no meaningful second packet. */
  if(layout==4)memcpy(buffer.data,&first,16);
  struct sk_buff skb={len,buffer.data};
  unsigned expected_calls=0;u32 expected_perms[2];u16 expected_types[2];int expected=0;
  for(unsigned i=0;i<count;i++) {
   u32 perm=0;int rc=legacy_selinux_nlmsg_lookup(classes[c],messages[i],&perm);
   if(rc==-EINVAL) {if(enforcing&&!unknown){expected=-EINVAL;break;}continue;}
   if(rc==-ENOENT)continue;assert(rc==0);
   if(kernel && (!x || !always))continue;
   expected_perms[expected_calls]=perm;expected_types[expected_calls++]=messages[i];
   if(callback_error){expected=callback_error;break;}
  }
  inject_snapshot=injection==1;inject_call=injection>=2?injection-1:0;
  int changed=injection==1 || (inject_call && inject_call<=expected_calls);
  if(!expected && changed)expected=-EAGAIN;
  int rc=selinux_nlmsg_perm(&sk,&skb);
  assert(rc==expected && callbacks==expected_calls && lock_depth==0);
  assert(base_calls==(x?0:expected_calls) && ext_calls==(x?expected_calls:0));
  for(unsigned i=0;i<callbacks;i++){assert(seen_perms[i]==expected_perms[i]);if(x)assert(seen_types[i]==expected_types[i]);}
  packets++;
 }
 setup(0,0,0,0,1);struct sock missing={NULL,0};struct sk_buff empty={0,NULL};
 assert(selinux_nlmsg_perm(&missing,&empty)==-EFAULT);
 printf("PASS: %lu lookup/stability, %lu packet/error/reload-injection, %lu snapshot-state scenarios\n",lookups,packets,states);
 return 0;
}
''')
# Bind host ABI to the target-compiled UAPI layout instead of guessing it.
source='\n'.join(parts)
source=source.replace('int main(void) {',f'_Static_assert(sizeof(struct nlmsghdr)=={constants["sizeof(struct nlmsghdr)"]},"target nlmsghdr size");\n_Static_assert(offsetof(struct nlmsghdr,nlmsg_type)=={constants["__builtin_offsetof(struct nlmsghdr, nlmsg_type)"]},"target type offset");\nint main(void) {{',1)
with tempfile.TemporaryDirectory(prefix='netlink-snapshot-') as d:
 t=Path(d);(t/'test.c').write_text(source)
 subprocess.run(['clang','-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-sign-compare','-fsanitize=address,undefined',str(t/'test.c'),'-o',str(t/'test')],check=True)
 result=subprocess.run([str(t/'test')],check=True,capture_output=True,text=True);print(result.stdout,end='')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
files=[a.kernel/(rel+x) for x in ['hooks.c','nlmsgtab.c','ss/services.c','include/security.h']]+[a.before/(rel+'nlmsgtab.c'),a.constants]
a.report.write_text(json.dumps({'passed':True,'scope':__doc__,'result':result.stdout.strip(),'inputs_sha256':{str(f):sha(f) for f in files},'runner_sha256':sha(Path(__file__)),'sanitizers':['address','undefined'],'hardware_tested':False,'live_reload_validated':False,'policycap9_guard_removed':False},indent=2)+'\n')
