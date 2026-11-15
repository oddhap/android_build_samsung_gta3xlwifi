#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual qtaguid UID deletion with explicit RB/list/lock/credential/socket fixtures.

Uses unchanged full kernel source, including real ctrl_cmd_delete and tag-ref
retirement. This is not kernel/hardware execution or a race validation.
"""
import argparse,fcntl,hashlib,importlib.util,json,os,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['kernel','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();K=a.kernel.resolve();O=a.output.resolve();assert not O.exists()
lock=Path('/srv/android/logs/lineage-24.0-arm64/build.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);O.mkdir(parents=True)
reference=Path(__file__).with_name('test-kernel-qtaguid-socket-owned.py');spec=importlib.util.spec_from_file_location('owned_reference',reference);ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)
source=K/'net/netfilter/xt_qtaguid.c';header=K/'include/uapi/linux/netfilter/xt_qtaguid_sock.h';text=source.read_text()
preamble=ref.PREAMBLE.replace('unsigned sockets_tagged,sockets_untagged;', 'unsigned sockets_tagged,sockets_untagged,delete_cmds;')
preamble+=r'''
#define get_atag_from_tag(t) ((t)&0xffffffff00000000ULL)
struct tag_counter_set {struct tag_node tn;int active_set;};
struct tag_stat {struct tag_node tn;};
struct iface_stat {struct list_head list;int tag_stat_list_lock;struct rb_root tag_stat_tree;char ifname[16];};
static struct rb_root tag_counter_set_tree=RB_ROOT;
static int tag_counter_set_list_lock,iface_stat_list_lock;
static struct list_head iface_stat_list={&iface_stat_list,&iface_stat_list};
#define list_for_each_entry(p,h,m) for((p)=list_entry((h)->next,__typeof__(*(p)),m);&(p)->m!=(h);(p)=list_entry((p)->m.next,__typeof__(*(p)),m))
'''
names=ref.NAMES+['tag_counter_set_tree_search','put_tag_ref_tree','ctrl_cmd_delete']
test=ref.TEST;assert test.count('int main(')==1;test=test.replace('int main(', 'static int previous_socket_owned_tests(',1)
test+=r'''
int main(void){CHECK(previous_socket_owned_tests()==0);unsigned begin=checks;
 for(bool owned=false;;owned=true){
  struct file f=session(200,owned);tag(0,1,10001);tag(1,2,10001);tag(2,3,10002);
  CHECK(sock_tag_tree_search(&sock_tag_tree,&socks[0])&&sock_tag_tree_search(&sock_tag_tree,&socks[1]));
  struct tag_counter_set*tcs=kzalloc(sizeof(*tcs),GFP_ATOMIC);CHECK(tcs);tcs->tn.tag=10001;tcs->active_set=1;tag_node_tree_insert(&tcs->tn,&tag_counter_set_tree);
  struct iface_stat iface={0};INIT_LIST_HEAD(&iface.list);iface.tag_stat_tree=RB_ROOT;strcpy(iface.ifname,"wlan0");list_add(&iface.list,&iface_stat_list);
  struct tag_stat*stat=kzalloc(sizeof(*stat),GFP_ATOMIC);CHECK(stat);stat->tn.tag=combine_atag_with_uid(make_atag_from_value(1),10001);tag_node_tree_insert(&stat->tn,&iface.tag_stat_tree);
  CHECK(ctrl_cmd_delete("d 0 10001")==0);CHECK(!sock_tag_tree_search(&sock_tag_tree,&socks[0])&&!sock_tag_tree_search(&sock_tag_tree,&socks[1]));CHECK(sock_tag_tree_search(&sock_tag_tree,&socks[2]));CHECK(!tag_counter_set_tree.rb_node&&!iface.tag_stat_tree.rb_node);CHECK(socks[0].refs==1&&socks[1].refs==1&&socks[2].refs==2);CHECK(ctrl_cmd_delete("d 0 10001")==0);
  list_del(&iface.list);CHECK(ctrl_cmd_delete("d 0 10002")==0);release(&f);empty();
  if(owned)break;
 }
 // Targeted nonzero-tag deletion must leave the other tag and UID intact.
 {struct file f=session(201,true);tag(0,1,10001);tag(1,2,10001);tag(2,1,10002);CHECK(ctrl_cmd_delete("d 4294967296 10001")==0);CHECK(!sock_tag_tree_search(&sock_tag_tree,&socks[0])&&sock_tag_tree_search(&sock_tag_tree,&socks[1])&&sock_tag_tree_search(&sock_tag_tree,&socks[2]));as(202,10003);CHECK(ctrl_cmd_delete("d 0 10001")==-EPERM);as(201,0);CHECK(ctrl_cmd_delete("d 0 10001")==0&&ctrl_cmd_delete("d 0 10002")==0);release(&f);empty();}
 // A new socket tagged after completed UID retirement survives another UID's cleanup.
 {struct file f=session(203,true);tag(0,1,10001);CHECK(ctrl_cmd_delete("d 0 10001")==0);tag(0,2,10001);tag(1,1,10002);CHECK(ctrl_cmd_delete("d 0 10002")==0&&sock_tag_tree_search(&sock_tag_tree,&socks[0]));CHECK(ctrl_cmd_delete("d 0 10001")==0);release(&f);empty();}
 printf("kernel_uid_cleanup_checks=%u total_checks=%u\n",checks-begin,checks);return 0;
}
'''
# The old main relied on main's implicit return0; make its replay return explicit.
pos=test.index('static int previous_socket_owned_tests(');end=test.index('\nint main(void)',pos);part=test[pos:end];last=part.rfind('}');part=part[:last]+'return 0;\n'+part[last:];test=test[:pos]+part+test[end:]
(O/'test.c').write_text(preamble+'\n'+header.read_text()+'\n'+'\n\n'.join(ref.extract(text,n) for n in names)+test)
cmd=['cc','-std=gnu11','-Wall','-Werror','-O1','-g','-fsanitize=undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer',str(O/'test.c'),'-o',str(O/'test')]
x=subprocess.run(cmd,capture_output=True,text=True);(O/'compile.log').write_text(x.stdout+x.stderr);assert x.returncode==0,x.stderr[-10000:]
x=subprocess.run([str(O/'test')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1'});(O/'test.log').write_text(x.stdout+x.stderr);assert x.returncode==0 and not x.stderr,(x.stdout,x.stderr);m=re.search(r'kernel_uid_cleanup_checks=(\d+) total_checks=(\d+)\n$',x.stdout);assert m
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();paths=[Path(__file__),reference,source,header,O/'test.c']
(O/'report.json').write_text(json.dumps({'passed':True,'scope':__doc__,'total_checks':int(m[2]),'kernel_uid_cleanup_checks':int(m[1]),'actual_functions':names,'inputs_sha256':{str(p):sha(p) for p in paths},'command':cmd,'hardware_tested':False,'flash_ready':False},indent=2)+'\n');print(x.stdout.strip())
