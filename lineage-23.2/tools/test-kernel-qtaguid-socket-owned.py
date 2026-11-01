#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Extract actual qtaguid tag/untag/session/ioctl code and run C host fixtures.
Tree balancing, locks, credentials, socket lookup and allocator are fixtures.
No actual kernel/device, packet accounting, races or hardware are validated.
Usage: test-kernel-qtaguid-socket-owned.py STAGED_KERNEL
"""
import argparse
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile

NAMES = ['tag_node_tree_search','tag_node_tree_insert','tag_ref_tree_insert','tag_ref_tree_search',
 'sock_tag_tree_search','sock_tag_tree_insert','sock_tag_tree_erase','proc_qtu_data_tree_search',
 'proc_qtu_data_tree_insert','uid_tag_data_tree_insert','uid_tag_data_tree_search','get_uid_data',
 'new_tag_ref','lookup_tag_ref','get_tag_ref','put_utd_entry','free_tag_ref_from_utd_entry',
 'get_sock_stat_nl','ctrl_cmd_tag','qtaguid_untag','qtudev_open','qtudev_release','qtudev_ioctl']


def extract(text, name):
    m = re.search(r'^(?:static )?[\w *]+\b'+re.escape(name)+r'\([^;]*?\)\s*\{', text, re.M)
    if not m:
        raise ValueError('Missing production function: '+name)
    start = m.start()
    # Kernel functions here have braces in comments; remove comments only for
    # bracket counting, preserving byte offsets of every character.
    clean = re.sub(r'/\*.*?\*/|//[^\n]*', lambda m: ' '*len(m.group()), text, flags=re.S)
    clean = re.sub(r'"(?:\\.|[^"\\])*"', lambda m: ' '*len(m.group()), clean)
    brace = text.index('{', m.start(), m.end())
    count = 1
    pos = brace+1
    while count:
        if clean[pos] == '{': count += 1
        if clean[pos] == '}': count -= 1
        pos += 1
    return text[start:pos]

PREAMBLE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/ioctl.h>
#include <sys/socket.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)) { fprintf(stderr,"line %d: %s\n",__LINE__,#x); abort(); } } while(0)
#define BUG_ON(x) CHECK(!(x))
#define BUG() abort()
#define unlikely(x) (x)
#define MT_DEBUG(...) ((void)0)
#define CT_DEBUG(...) ((void)0)
#define DR_DEBUG(...) ((void)0)
#define RB_DEBUG(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_warn_once(...) ((void)0)
#define prdebug_full_state_locked(...) ((void)0)
#define GFP_ATOMIC 0
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define IS_ERR_OR_NULL(p) (!(p)||IS_ERR(p))
static int allocations;
static void *allocate(size_t n) { void *p=calloc(1,n); CHECK(p); ++allocations; return p; }
#define kzalloc(n,gfp) allocate(n)
static void kfree(void *p) { CHECK(p); --allocations; free(p); }
struct rb_node { struct rb_node *rb_left,*rb_right,*parent; };
struct rb_root { struct rb_node *rb_node; };
#define RB_ROOT ((struct rb_root){NULL})
#define RB_EMPTY_ROOT(r) (!(r)->rb_node)
#define rb_entry(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
static void rb_link_node(struct rb_node*n,struct rb_node*p,struct rb_node**slot) { n->parent=p; *slot=n; }
#define rb_insert_color(n,r) ((void)0)
static struct rb_node *rb_first(struct rb_root*r) { struct rb_node*n=r->rb_node; if(n) while(n->rb_left)n=n->rb_left; return n; }
static struct rb_node *rb_next(struct rb_node*n) { if(n->rb_right) { n=n->rb_right; while(n->rb_left)n=n->rb_left; return n; } while(n->parent&&n==n->parent->rb_right)n=n->parent; return n->parent; }
static void replace(struct rb_root*r,struct rb_node*old,struct rb_node*n) { if(!old->parent)r->rb_node=n; else if(old==old->parent->rb_left)old->parent->rb_left=n; else old->parent->rb_right=n; if(n)n->parent=old->parent; }
static void rb_erase(struct rb_node*z,struct rb_root*r) {
 if(!z->rb_left)replace(r,z,z->rb_right);
 else if(!z->rb_right)replace(r,z,z->rb_left);
 else { struct rb_node*y=z->rb_right; while(y->rb_left)y=y->rb_left;
  if(y->parent!=z) { replace(r,y,y->rb_right); y->rb_right=z->rb_right; y->rb_right->parent=y; }
  replace(r,z,y); y->rb_left=z->rb_left; y->rb_left->parent=y; }
 z->rb_left=z->rb_right=z->parent=NULL;
}
struct list_head { struct list_head *next,*prev; };
#define INIT_LIST_HEAD(h) do { (h)->next=(h);(h)->prev=(h); } while(0)
static int list_empty(struct list_head*h) { return h->next==h; }
static void list_add(struct list_head*n,struct list_head*h) { n->next=h->next;n->prev=h;h->next->prev=n;h->next=n; }
static void list_del(struct list_head*n) { n->next->prev=n->prev;n->prev->next=n->next;n->next=n->prev=NULL; }
static void list_del_init(struct list_head*n) { list_del(n);INIT_LIST_HEAD(n); }
#define list_entry(p,t,m) rb_entry(p,t,m)
#define list_for_each_safe(p,n,h) for((p)=(h)->next,(n)=(p)->next;(p)!=(h);(p)=(n),(n)=(p)->next)
static int sock_tag_list_lock,uid_tag_data_tree_lock;
static void spin_lock_bh(int*l) { CHECK(!*l); *l=1; }
static void spin_unlock_bh(int*l) { CHECK(*l); *l=0; }
typedef unsigned long long tag_t;
typedef unsigned kuid_t;
struct sock { int refs;int sk_family; };
struct file { void*private_data; long f_count; };
struct inode { int unused; };
struct socket { struct sock*sk;struct file*file; };
struct tag_node { struct rb_node node;tag_t tag; };
struct tag_ref { struct tag_node tn;int num_sock_tags; };
struct uid_tag_data { struct rb_node node;uid_t uid;int num_active_tags,num_pqd;struct rb_root tag_ref_tree; };
struct sock_tag { struct rb_node sock_node;struct sock*sk;struct list_head list;pid_t pid;tag_t tag; };
struct proc_qtu_data { struct rb_node node;pid_t pid;struct uid_tag_data*parent_tag_data;bool socket_owned;struct list_head sock_tag_list; };
static struct rb_root sock_tag_tree=RB_ROOT,uid_tag_data_tree=RB_ROOT,proc_qtu_data_tree=RB_ROOT;
static int max_sock_tags=1024;
static bool module_passive,qtu_proc_handling_passive,admin=true;
static struct { pid_t pid,tgid;uid_t uid; } task={1,1,0};
#define current (&task)
#define current_euid() (current->uid)
#define current_fsuid() (current->uid)
#define current_uid() (current->uid)
#define GLOBAL_ROOT_UID 0
#define CAP_NET_ADMIN 12
#define capable(cap) (admin)
#define uid_eq(a,b) ((a)==(b))
#define from_kuid(ns,u) (u)
#define from_kgid(ns,u) (u)
#define make_kuid(ns,u) (u)
#define atomic_long_read(p) (*(p))
#define atomic_read(p) (*(p))
#define atomic64_inc(p) (++*(p))
static struct { unsigned sockets_tagged,sockets_untagged; } qtu_events;
#define QTU_DEV_NAME "xt_qtaguid"
#define make_atag_from_value(v) ((tag_t)(v)<<32)
#define valid_atag(v) (!((v)&0xffffffffULL))
#define combine_atag_with_uid(t,u) ((t)|(u))
#define get_uid_from_tag(t) ((uid_t)(t))
static int tag_compare(tag_t a,tag_t b) { return (a>b)-(a<b); }
static bool can_impersonate_uid(uid_t u) { return current->uid==0||current->uid==u; }
static void sock_hold(struct sock*s) { CHECK(s->refs>0);++s->refs; }
static void sock_put(struct sock*s) { CHECK(s->refs>1);--s->refs; }
static struct sock socks[16];static struct file socket_files[16];static struct socket sockets[16];
static struct socket*sockfd_lookup(int fd,int*err) { if(fd<0||fd>=16) { *err=-EBADF;return NULL; } ++sockets[fd].file->f_count;return &sockets[fd]; }
static void sockfd_put(struct socket*s) { CHECK(s->file->f_count==2);--s->file->f_count; }
'''

TEST = r'''
static void as(pid_t pid,uid_t uid) { current->pid=current->tgid=pid;current->uid=uid; }
static void tag(int fd,unsigned tag,uid_t uid) { char b[96];snprintf(b,sizeof(b),"t %d %llu %u",fd,(tag_t)tag<<32,uid);CHECK(ctrl_cmd_tag(b)==0); }
static struct file session(pid_t pid,bool owned) { struct file f={0}; as(pid,0);CHECK(qtudev_open(NULL,&f)==0);if(owned)CHECK(qtudev_ioctl(&f,QTAGUID_SOCKET_OWNED_SESSION,0)==0);return f; }
static void release(struct file*f) { CHECK(qtudev_release(NULL,f)==0);CHECK(!f->private_data); }
static void empty(void) { CHECK(!sock_tag_tree.rb_node);CHECK(!uid_tag_data_tree.rb_node);CHECK(!proc_qtu_data_tree.rb_node);CHECK(!allocations);for(int i=0;i<16;++i)CHECK(socks[i].refs==1); }
int main(void) {
 for(int i=0;i<16;++i) { socks[i].refs=1;socks[i].sk_family=AF_INET;socket_files[i].f_count=1;sockets[i].sk=&socks[i];sockets[i].file=&socket_files[i]; }
 // Private mode never changes legacy clients by default.
 { struct file f=session(10,false);tag(0,7,10001);CHECK(get_sock_stat_nl(&socks[0])->pid==10);as(999,0);release(&f);empty(); }
 // Gate: command/argument/initial-uid/capability/passive/ownership/list state.
 { struct file f=session(20,false);struct proc_qtu_data*p=f.private_data;
  CHECK(!p->socket_owned);CHECK(qtudev_ioctl(&f,0,0)==-ENOTTY);
  CHECK(qtudev_ioctl(&f,QTAGUID_SOCKET_OWNED_SESSION,1)==-EINVAL);
  as(20,1000);CHECK(qtudev_ioctl(&f,QTAGUID_SOCKET_OWNED_SESSION,0)==-EPERM);
  as(20,0);admin=false;CHECK(qtudev_ioctl(&f,QTAGUID_SOCKET_OWNED_SESSION,0)==-EPERM);admin=true;
  module_passive=true;CHECK(qtudev_ioctl(&f,QTAGUID_SOCKET_OWNED_SESSION,0)==-EOPNOTSUPP);module_passive=false;
  qtu_proc_handling_passive=true;CHECK(qtudev_ioctl(&f,QTAGUID_SOCKET_OWNED_SESSION,0)==-EOPNOTSUPP);qtu_proc_handling_passive=false;
  as(21,0);CHECK(qtudev_ioctl(&f,QTAGUID_SOCKET_OWNED_SESSION,0)==-EPERM);as(20,0);
  struct file missing={0};CHECK(qtudev_ioctl(&missing,QTAGUID_SOCKET_OWNED_SESSION,0)==-EPERM);
  tag(0,8,10001);CHECK(qtudev_ioctl(&f,QTAGUID_SOCKET_OWNED_SESSION,0)==-EBUSY);CHECK(!p->socket_owned);release(&f);empty(); }
 // Reject unsupported persistent socket families before allocating resources.
 { struct file f=session(25,true);socks[0].sk_family=AF_UNIX;
  CHECK(ctrl_cmd_tag("t 0 4294967296 10001")==-EAFNOSUPPORT);
  CHECK(!get_sock_stat_nl(&socks[0]) && socks[0].refs==1);
  CHECK(!uid_tag_data_tree_search(&uid_tag_data_tree,10001));
  socks[0].sk_family=AF_INET6;tag(0,1,10001);release(&f);
  CHECK(qtaguid_untag(&sockets[0],true)==0);socks[0].sk_family=AF_INET;empty(); }
 // Legacy Unix tags retain their old process-session cleanup behavior.
 { struct file f=session(26,false);socks[0].sk_family=AF_UNIX;tag(0,1,10001);
  release(&f);socks[0].sk_family=AF_INET;empty(); }
 // Reject promotion of a pre-existing legacy Unix tag, preserving old ownership.
 { struct file old=session(27,false);socks[0].sk_family=AF_UNIX;tag(0,1,10001);
  struct file modern=session(28,true);
  CHECK(ctrl_cmd_tag("t 0 8589934592 10002")==-EAFNOSUPPORT);
  CHECK(get_sock_stat_nl(&socks[0])->pid==27);
  CHECK(!uid_tag_data_tree_search(&uid_tag_data_tree,10002));
  release(&old);release(&modern);socks[0].sk_family=AF_INET;empty(); }
 // Tag survives session destruction and PID reuse; final close from other app retires it.
 { struct file f=session(30,true);tag(0,9,10001);CHECK(get_sock_stat_nl(&socks[0])->pid==0);
  CHECK(list_empty(&((struct proc_qtu_data*)f.private_data)->sock_tag_list));release(&f);
  CHECK(get_sock_stat_nl(&socks[0]));CHECK(socks[0].refs==2);
  struct file reused=session(30,false);release(&reused);CHECK(get_sock_stat_nl(&socks[0]));
  as(1234,10001);CHECK(qtaguid_untag(&sockets[0],true)==0);CHECK(qtaguid_untag(&sockets[0],true)==-EINVAL);empty(); }
 // Two sockets share one reference; explicit untag and final release retire only last.
 { struct file f=session(40,true);tag(0,1,10001);tag(1,1,10001);release(&f);
  CHECK(uid_tag_data_tree_search(&uid_tag_data_tree,10001)->num_active_tags==1);
  CHECK(qtaguid_untag(&sockets[0],false)==0);CHECK(uid_tag_data_tree_search(&uid_tag_data_tree,10001)->num_active_tags==1);
  CHECK(qtaguid_untag(&sockets[1],true)==0);empty(); }
 // Retag across UID/tag and same-tag operations do not leak reference/UID data.
 { struct file f=session(50,true);tag(0,1,10001);release(&f);struct file g=session(51,true);
  tag(0,2,10002);CHECK(!uid_tag_data_tree_search(&uid_tag_data_tree,10001));
  tag(0,2,10002);tag(0,3,10002);CHECK(uid_tag_data_tree_search(&uid_tag_data_tree,10002)->num_active_tags==1);
  release(&g);CHECK(qtaguid_untag(&sockets[0],true)==0);empty(); }
 // Promote legacy tag; its former process session cannot erase the promoted tag.
 { struct file old=session(60,false);tag(0,1,10001);struct file modern=session(61,true);
  tag(0,2,10002);CHECK(get_sock_stat_nl(&socks[0])->pid==0);
  release(&old);release(&modern);CHECK(get_sock_stat_nl(&socks[0]));CHECK(qtaguid_untag(&sockets[0],true)==0);empty(); }
 // Legacy retag of a socket-owned tag must not downgrade its lifetime.
 { struct file old=session(70,true);tag(0,1,0);release(&old);struct file legacy=session(71,false);
  tag(0,2,10001);release(&legacy);CHECK(get_sock_stat_nl(&socks[0])->pid==0);
  CHECK(qtaguid_untag(&sockets[0],false)==0);empty(); }
 // Churn can retire socket-owned refs while session stays live; no dangling parent UID.
 { struct file f=session(80,true);for(int i=0;i<2048;++i) { tag(0,(unsigned)i,0);CHECK(qtaguid_untag(&sockets[0],true)==0); }
  CHECK(((struct proc_qtu_data*)f.private_data)->parent_tag_data->num_active_tags==0);release(&f);empty(); }
 CHECK(!sock_tag_list_lock&&!uid_tag_data_tree_lock);
 printf("PASS: %u assertions, extracted production tag/untag/session/ioctl/ref helpers; fixture kernel primitives, NOT kernel execution\n",checks);
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('kernel', type=Path)
    a = p.parse_args()
    if not sys.platform.startswith('linux'):
        p.error('Linux host headers required; this is a kernel-primitive fixture test')
    k = a.kernel.resolve()
    source = (k/'net/netfilter/xt_qtaguid.c').read_text()
    header = (k/'include/uapi/linux/netfilter/xt_qtaguid_sock.h').read_text()
    with tempfile.TemporaryDirectory(prefix='kernel-qtaguid-owned-') as d:
        d = Path(d)
        (d/'test.c').write_text(PREAMBLE+'\n'+header+'\n'+'\n\n'.join(extract(source,n) for n in NAMES)+TEST)
        subprocess.run([os.environ.get('CC','cc'), '-std=gnu11','-Wall','-Werror','-O1','-g',
            '-fsanitize=address,undefined','-fno-omit-frame-pointer',str(d/'test.c'),'-o',str(d/'test')],check=True)
        subprocess.run([str(d/'test')],check=True)


if __name__ == '__main__':
    main()
