
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
static struct { unsigned sockets_tagged,sockets_untagged,delete_cmds; } qtu_events;
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

#define get_atag_from_tag(t) ((t)&0xffffffff00000000ULL)
struct tag_counter_set {struct tag_node tn;int active_set;};
struct tag_stat {struct tag_node tn;};
struct iface_stat {struct list_head list;int tag_stat_list_lock;struct rb_root tag_stat_tree;char ifname[16];};
static struct rb_root tag_counter_set_tree=RB_ROOT;
static int tag_counter_set_list_lock,iface_stat_list_lock;
static struct list_head iface_stat_list={&iface_stat_list,&iface_stat_list};
#define list_for_each_entry(p,h,m) for((p)=list_entry((h)->next,__typeof__(*(p)),m);&(p)->m!=(h);(p)=list_entry((p)->m.next,__typeof__(*(p)),m))

/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_XT_QTAGUID_SOCK_H
#define _UAPI_XT_QTAGUID_SOCK_H

#include <linux/ioctl.h>

/* Private, opt-in gta3xlwifi ABI. No argument, same command on 32/64 bit.
 * Requires initial-namespace root plus CAP_NET_ADMIN and an empty own session.
 * New/retagged sockets then own their tags until explicit untag, UID deletion
 * or inet_release, not until the tagging daemon's process/session exits.
 * This does not authorize a caller or implement accounting budgets/readiness.
 */
#define QTAGUID_SOCKET_OWNED_SESSION _IO('q', 0x51)

#endif

static struct tag_node *tag_node_tree_search(struct rb_root *root, tag_t tag)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct tag_node *data = rb_entry(node, struct tag_node, node);
		int result;
		RB_DEBUG("qtaguid: tag_node_tree_search(0x%llx): "
			 " node=%p data=%p\n", tag, node, data);
		result = tag_compare(tag, data->tag);
		RB_DEBUG("qtaguid: tag_node_tree_search(0x%llx): "
			 " data.tag=0x%llx (uid=%u) res=%d\n",
			 tag, data->tag, get_uid_from_tag(data->tag), result);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

static void tag_node_tree_insert(struct tag_node *data, struct rb_root *root)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct tag_node *this = rb_entry(*new, struct tag_node,
						 node);
		int result = tag_compare(data->tag, this->tag);
		RB_DEBUG("qtaguid: %s(): tag=0x%llx"
			 " (uid=%u)\n", __func__,
			 this->tag,
			 get_uid_from_tag(this->tag));
		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			BUG();
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
}

static void tag_ref_tree_insert(struct tag_ref *data, struct rb_root *root)
{
	tag_node_tree_insert(&data->tn, root);
}

static struct tag_ref *tag_ref_tree_search(struct rb_root *root, tag_t tag)
{
	struct tag_node *node = tag_node_tree_search(root, tag);
	if (!node)
		return NULL;
	return rb_entry(&node->node, struct tag_ref, tn.node);
}

static struct sock_tag *sock_tag_tree_search(struct rb_root *root,
					     const struct sock *sk)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct sock_tag *data = rb_entry(node, struct sock_tag,
						 sock_node);
		if (sk < data->sk)
			node = node->rb_left;
		else if (sk > data->sk)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

static void sock_tag_tree_insert(struct sock_tag *data, struct rb_root *root)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct sock_tag *this = rb_entry(*new, struct sock_tag,
						 sock_node);
		parent = *new;
		if (data->sk < this->sk)
			new = &((*new)->rb_left);
		else if (data->sk > this->sk)
			new = &((*new)->rb_right);
		else
			BUG();
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->sock_node, parent, new);
	rb_insert_color(&data->sock_node, root);
}

static void sock_tag_tree_erase(struct rb_root *st_to_free_tree)
{
	struct rb_node *node;
	struct sock_tag *st_entry;

	node = rb_first(st_to_free_tree);
	while (node) {
		st_entry = rb_entry(node, struct sock_tag, sock_node);
		node = rb_next(node);
		CT_DEBUG("qtaguid: %s(): "
			 "erase st: sk=%p tag=0x%llx (uid=%u)\n", __func__,
			 st_entry->sk,
			 st_entry->tag,
			 get_uid_from_tag(st_entry->tag));
		rb_erase(&st_entry->sock_node, st_to_free_tree);
		sock_put(st_entry->sk);
		kfree(st_entry);
	}
}

static struct proc_qtu_data *proc_qtu_data_tree_search(struct rb_root *root,
						       const pid_t pid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct proc_qtu_data *data = rb_entry(node,
						      struct proc_qtu_data,
						      node);
		if (pid < data->pid)
			node = node->rb_left;
		else if (pid > data->pid)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

static void proc_qtu_data_tree_insert(struct proc_qtu_data *data,
				      struct rb_root *root)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct proc_qtu_data *this = rb_entry(*new,
						      struct proc_qtu_data,
						      node);
		parent = *new;
		if (data->pid < this->pid)
			new = &((*new)->rb_left);
		else if (data->pid > this->pid)
			new = &((*new)->rb_right);
		else
			BUG();
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
}

static void uid_tag_data_tree_insert(struct uid_tag_data *data,
				     struct rb_root *root)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct uid_tag_data *this = rb_entry(*new,
						     struct uid_tag_data,
						     node);
		parent = *new;
		if (data->uid < this->uid)
			new = &((*new)->rb_left);
		else if (data->uid > this->uid)
			new = &((*new)->rb_right);
		else
			BUG();
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
}

static struct uid_tag_data *uid_tag_data_tree_search(struct rb_root *root,
						     uid_t uid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct uid_tag_data *data = rb_entry(node,
						     struct uid_tag_data,
						     node);
		if (uid < data->uid)
			node = node->rb_left;
		else if (uid > data->uid)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

struct uid_tag_data *get_uid_data(uid_t uid, bool *found_res)
{
	struct uid_tag_data *utd_entry;

	/* Look for top level uid_tag_data for the UID */
	utd_entry = uid_tag_data_tree_search(&uid_tag_data_tree, uid);
	DR_DEBUG("qtaguid: get_uid_data(%u) utd=%p\n", uid, utd_entry);

	if (found_res)
		*found_res = utd_entry;
	if (utd_entry)
		return utd_entry;

	utd_entry = kzalloc(sizeof(*utd_entry), GFP_ATOMIC);
	if (!utd_entry) {
		pr_err("qtaguid: get_uid_data(%u): "
		       "tag data alloc failed\n", uid);
		return ERR_PTR(-ENOMEM);
	}

	utd_entry->uid = uid;
	utd_entry->tag_ref_tree = RB_ROOT;
	uid_tag_data_tree_insert(utd_entry, &uid_tag_data_tree);
	DR_DEBUG("qtaguid: get_uid_data(%u) new utd=%p\n", uid, utd_entry);
	return utd_entry;
}

static struct tag_ref *new_tag_ref(tag_t new_tag,
				   struct uid_tag_data *utd_entry)
{
	struct tag_ref *tr_entry;
	int res;

	if (utd_entry->num_active_tags + 1 > max_sock_tags) {
		pr_info("qtaguid: new_tag_ref(0x%llx): "
			"tag ref alloc quota exceeded. max=%d\n",
			new_tag, max_sock_tags);
		res = -EMFILE;
		goto err_res;

	}

	tr_entry = kzalloc(sizeof(*tr_entry), GFP_ATOMIC);
	if (!tr_entry) {
		pr_err("qtaguid: new_tag_ref(0x%llx): "
		       "tag ref alloc failed\n",
		       new_tag);
		res = -ENOMEM;
		goto err_res;
	}
	tr_entry->tn.tag = new_tag;
	/* tr_entry->num_sock_tags  handled by caller */
	utd_entry->num_active_tags++;
	tag_ref_tree_insert(tr_entry, &utd_entry->tag_ref_tree);
	DR_DEBUG("qtaguid: new_tag_ref(0x%llx): "
		 " inserted new tag ref %p\n",
		 new_tag, tr_entry);
	return tr_entry;

err_res:
	return ERR_PTR(res);
}

static struct tag_ref *lookup_tag_ref(tag_t full_tag,
				      struct uid_tag_data **utd_res)
{
	struct uid_tag_data *utd_entry;
	struct tag_ref *tr_entry;
	bool found_utd;
	uid_t uid = get_uid_from_tag(full_tag);

	DR_DEBUG("qtaguid: lookup_tag_ref(tag=0x%llx (uid=%u))\n",
		 full_tag, uid);

	utd_entry = get_uid_data(uid, &found_utd);
	if (IS_ERR_OR_NULL(utd_entry)) {
		if (utd_res)
			*utd_res = utd_entry;
		return NULL;
	}

	tr_entry = tag_ref_tree_search(&utd_entry->tag_ref_tree, full_tag);
	if (utd_res)
		*utd_res = utd_entry;
	DR_DEBUG("qtaguid: lookup_tag_ref(0x%llx) utd_entry=%p tr_entry=%p\n",
		 full_tag, utd_entry, tr_entry);
	return tr_entry;
}

static struct tag_ref *get_tag_ref(tag_t full_tag,
				   struct uid_tag_data **utd_res)
{
	struct uid_tag_data *utd_entry;
	struct tag_ref *tr_entry;

	DR_DEBUG("qtaguid: get_tag_ref(0x%llx)\n",
		 full_tag);
	tr_entry = lookup_tag_ref(full_tag, &utd_entry);
	BUG_ON(IS_ERR_OR_NULL(utd_entry));
	if (!tr_entry)
		tr_entry = new_tag_ref(full_tag, utd_entry);

	if (utd_res)
		*utd_res = utd_entry;
	DR_DEBUG("qtaguid: get_tag_ref(0x%llx) utd=%p tr=%p\n",
		 full_tag, utd_entry, tr_entry);
	return tr_entry;
}

static void put_utd_entry(struct uid_tag_data *utd_entry)
{
	/* Are we done with the UID tag data entry? */
	if (RB_EMPTY_ROOT(&utd_entry->tag_ref_tree) &&
		!utd_entry->num_pqd) {
		DR_DEBUG("qtaguid: %s(): "
			 "erase utd_entry=%p uid=%u "
			 "by pid=%u tgid=%u uid=%u\n", __func__,
			 utd_entry, utd_entry->uid,
			 current->pid, current->tgid, from_kuid(&init_user_ns, current_fsuid()));
		BUG_ON(utd_entry->num_active_tags);
		rb_erase(&utd_entry->node, &uid_tag_data_tree);
		kfree(utd_entry);
	} else {
		DR_DEBUG("qtaguid: %s(): "
			 "utd_entry=%p still has %d tags %d proc_qtu_data\n",
			 __func__, utd_entry, utd_entry->num_active_tags,
			 utd_entry->num_pqd);
		BUG_ON(!(utd_entry->num_active_tags ||
			 utd_entry->num_pqd));
	}
}

static void free_tag_ref_from_utd_entry(struct tag_ref *tr_entry,
					struct uid_tag_data *utd_entry)
{
	DR_DEBUG("qtaguid: %s(): %p tag=0x%llx (uid=%u)\n", __func__,
		 tr_entry, tr_entry->tn.tag,
		 get_uid_from_tag(tr_entry->tn.tag));
	if (!tr_entry->num_sock_tags) {
		BUG_ON(!utd_entry->num_active_tags);
		utd_entry->num_active_tags--;
		rb_erase(&tr_entry->tn.node, &utd_entry->tag_ref_tree);
		DR_DEBUG("qtaguid: %s(): erased %p\n", __func__, tr_entry);
		kfree(tr_entry);
	}
}

static struct sock_tag *get_sock_stat_nl(const struct sock *sk)
{
	MT_DEBUG("qtaguid: get_sock_stat_nl(sk=%p)\n", sk);
	return sock_tag_tree_search(&sock_tag_tree, sk);
}

static int ctrl_cmd_tag(const char *input)
{
	char cmd;
	int sock_fd = 0;
	kuid_t uid;
	unsigned int uid_int = 0;
	tag_t acct_tag = make_atag_from_value(0);
	tag_t full_tag;
	bool socket_owned;
	struct socket *el_socket;
	int res, argc;
	struct sock_tag *sock_tag_entry;
	struct tag_ref *tag_ref_entry;
	struct uid_tag_data *uid_tag_data_entry;
	struct proc_qtu_data *pqd_entry;

	/* Unassigned args will get defaulted later. */
	argc = sscanf(input, "%c %d %llu %u", &cmd, &sock_fd, &acct_tag, &uid_int);
	uid = make_kuid(&init_user_ns, uid_int);
	CT_DEBUG("qtaguid: ctrl_tag(%s): argc=%d cmd=%c sock_fd=%d "
		 "acct_tag=0x%llx uid=%u\n", input, argc, cmd, sock_fd,
		 acct_tag, uid_int);
	if (argc < 2) {
		res = -EINVAL;
		goto err;
	}
	el_socket = sockfd_lookup(sock_fd, &res);  /* This locks the file */
	if (!el_socket) {
		pr_info("qtaguid: ctrl_tag(%s): failed to lookup"
			" sock_fd=%d err=%d pid=%u tgid=%u uid=%u\n",
			input, sock_fd, res, current->pid, current->tgid,
			from_kuid(&init_user_ns, current_fsuid()));
		goto err;
	}
	CT_DEBUG("qtaguid: ctrl_tag(%s): socket->...->sk_refcnt=%d ->sk=%p\n",
		 input, atomic_read(&el_socket->sk->sk_refcnt),
		 el_socket->sk);
	if (argc < 3) {
		acct_tag = make_atag_from_value(0);
	} else if (!valid_atag(acct_tag)) {
		pr_info("qtaguid: ctrl_tag(%s): invalid tag\n", input);
		res = -EINVAL;
		goto err_put;
	}
	CT_DEBUG("qtaguid: ctrl_tag(%s): "
		 "pid=%u tgid=%u uid=%u euid=%u fsuid=%u "
		 "ctrl.gid=%u in_group()=%d in_egroup()=%d\n",
		 input, current->pid, current->tgid,
		 from_kuid(&init_user_ns, current_uid()),
		 from_kuid(&init_user_ns, current_euid()),
		 from_kuid(&init_user_ns, current_fsuid()),
		 from_kgid(&init_user_ns, xt_qtaguid_ctrl_file->gid),
		 in_group_p(xt_qtaguid_ctrl_file->gid),
		 in_egroup_p(xt_qtaguid_ctrl_file->gid));
	if (argc < 4) {
		uid = current_fsuid();
		uid_int = from_kuid(&init_user_ns, uid);
	} else if (!can_impersonate_uid(uid)) {
		pr_info("qtaguid: ctrl_tag(%s): "
			"insufficient priv from pid=%u tgid=%u uid=%u\n",
			input, current->pid, current->tgid, from_kuid(&init_user_ns, current_fsuid()));
		res = -EPERM;
		goto err_put;
	}
	full_tag = combine_atag_with_uid(acct_tag, uid_int);

	spin_lock_bh(&sock_tag_list_lock);
	spin_lock_bh(&uid_tag_data_tree_lock);
	pqd_entry = proc_qtu_data_tree_search(&proc_qtu_data_tree, current->tgid);
	socket_owned = !IS_ERR_OR_NULL(pqd_entry) && pqd_entry->socket_owned;
	sock_tag_entry = get_sock_stat_nl(el_socket->sk);
	/* Only inet sockets have the required final file-release hook. Never
	 * create/promote a socket-owned Unix/packet tag with no cleanup path.
	 */
	if ((socket_owned || (sock_tag_entry && !sock_tag_entry->pid)) &&
	    (!el_socket->sk || (el_socket->sk->sk_family != AF_INET &&
			      el_socket->sk->sk_family != AF_INET6))) {
		res = -EAFNOSUPPORT;
		spin_unlock_bh(&uid_tag_data_tree_lock);
		spin_unlock_bh(&sock_tag_list_lock);
		goto err_put;
	}
	tag_ref_entry = get_tag_ref(full_tag, &uid_tag_data_entry);
	if (IS_ERR(tag_ref_entry)) {
		res = PTR_ERR(tag_ref_entry);
		spin_unlock_bh(&uid_tag_data_tree_lock);
		spin_unlock_bh(&sock_tag_list_lock);
		goto err_put;
	}
	tag_ref_entry->num_sock_tags++;
	if (sock_tag_entry) {
		struct tag_ref *prev_tag_ref_entry;

		CT_DEBUG("qtaguid: ctrl_tag(%s): retag for sk=%p "
			 "st@%p ...->sk_refcnt=%d\n",
			 input, el_socket->sk, sock_tag_entry,
			 atomic_read(&el_socket->sk->sk_refcnt));
		prev_tag_ref_entry = lookup_tag_ref(sock_tag_entry->tag,
						    &uid_tag_data_entry);
		BUG_ON(IS_ERR_OR_NULL(prev_tag_ref_entry));
		BUG_ON(prev_tag_ref_entry->num_sock_tags <= 0);
		prev_tag_ref_entry->num_sock_tags--;
		/* Once socket-owned, never reattach to a process lifetime. A
		 * privileged retag also safely promotes an existing legacy tag.
		 */
		if (socket_owned || !sock_tag_entry->pid) {
			if (sock_tag_entry->list.next)
				list_del_init(&sock_tag_entry->list);
			else
				INIT_LIST_HEAD(&sock_tag_entry->list);
			sock_tag_entry->pid = 0;
			free_tag_ref_from_utd_entry(prev_tag_ref_entry,
						   uid_tag_data_entry);
			put_utd_entry(uid_tag_data_entry);
		}
		sock_tag_entry->tag = full_tag;
	} else {
		CT_DEBUG("qtaguid: ctrl_tag(%s): newtag for sk=%p\n",
			 input, el_socket->sk);
		sock_tag_entry = kzalloc(sizeof(*sock_tag_entry),
					 GFP_ATOMIC);
		if (!sock_tag_entry) {
			pr_err("qtaguid: ctrl_tag(%s): "
			       "socket tag alloc failed\n",
			       input);
			BUG_ON(tag_ref_entry->num_sock_tags <= 0);
			tag_ref_entry->num_sock_tags--;
			free_tag_ref_from_utd_entry(tag_ref_entry,
						    uid_tag_data_entry);
			spin_unlock_bh(&uid_tag_data_tree_lock);
			spin_unlock_bh(&sock_tag_list_lock);
			res = -ENOMEM;
			goto err_put;
		}
		/*
		 * Hold the sk refcount here to make sure the sk pointer cannot
		 * be freed and reused
		 */
		sock_hold(el_socket->sk);
		sock_tag_entry->sk = el_socket->sk;
		sock_tag_entry->pid = socket_owned ? 0 : current->tgid;
		sock_tag_entry->tag = combine_atag_with_uid(acct_tag, uid_int);
		/*
		 * TODO: remove if, and start failing.
		 * At first, we want to catch user-space code that is not
		 * opening the /dev/xt_qtaguid.
		 */
		if (socket_owned) {
			/* No process list owns this reference: the existing inet
			 * final-release hook or explicit untag/delete releases it.
			 */
			INIT_LIST_HEAD(&sock_tag_entry->list);
		} else if (IS_ERR_OR_NULL(pqd_entry))
			pr_warn_once(
				"qtaguid: %s(): "
				"User space forgot to open /dev/xt_qtaguid? "
				"pid=%u tgid=%u uid=%u\n", __func__,
				current->pid, current->tgid,
				from_kuid(&init_user_ns, current_fsuid()));
		else
			list_add(&sock_tag_entry->list,
				 &pqd_entry->sock_tag_list);

		sock_tag_tree_insert(sock_tag_entry, &sock_tag_tree);
		atomic64_inc(&qtu_events.sockets_tagged);
	}
	spin_unlock_bh(&uid_tag_data_tree_lock);
	spin_unlock_bh(&sock_tag_list_lock);
	/* We keep the ref to the sk until it is untagged */
	CT_DEBUG("qtaguid: ctrl_tag(%s): done st@%p ...->sk_refcnt=%d\n",
		 input, sock_tag_entry,
		 atomic_read(&el_socket->sk->sk_refcnt));
	sockfd_put(el_socket);
	return 0;

err_put:
	CT_DEBUG("qtaguid: ctrl_tag(%s): done. ...->sk_refcnt=%d\n",
		 input, atomic_read(&el_socket->sk->sk_refcnt) - 1);
	/* Release the sock_fd that was grabbed by sockfd_lookup(). */
	sockfd_put(el_socket);
	return res;

err:
	CT_DEBUG("qtaguid: ctrl_tag(%s): done.\n", input);
	return res;
}

int qtaguid_untag(struct socket *el_socket, bool kernel)
{
	int res;
	pid_t pid;
	struct sock_tag *sock_tag_entry;
	struct tag_ref *tag_ref_entry;
	struct uid_tag_data *utd_entry;
	struct proc_qtu_data *pqd_entry;

	spin_lock_bh(&sock_tag_list_lock);
	sock_tag_entry = get_sock_stat_nl(el_socket->sk);
	if (!sock_tag_entry) {
		spin_unlock_bh(&sock_tag_list_lock);
		res = -EINVAL;
		return res;
	}
	/*
	 * The socket already belongs to the current process
	 * so it can do whatever it wants to it.
	 */
	rb_erase(&sock_tag_entry->sock_node, &sock_tag_tree);

	spin_lock_bh(&uid_tag_data_tree_lock);
	tag_ref_entry = lookup_tag_ref(sock_tag_entry->tag, &utd_entry);
	BUG_ON(!tag_ref_entry);
	BUG_ON(tag_ref_entry->num_sock_tags <= 0);
	if (kernel)
		pid = sock_tag_entry->pid;
	else
		pid = current->tgid;
	pqd_entry = sock_tag_entry->pid ? proc_qtu_data_tree_search(
		&proc_qtu_data_tree, pid) : NULL;
	/*
	 * TODO: remove if, and start failing.
	 * At first, we want to catch user-space code that is not
	 * opening the /dev/xt_qtaguid.
	 */
	if (sock_tag_entry->pid && IS_ERR_OR_NULL(pqd_entry))
		pr_warn_once("qtaguid: %s(): "
			     "User space forgot to open /dev/xt_qtaguid? "
			     "pid=%u tgid=%u sk_pid=%u, uid=%u\n", __func__,
			     current->pid, current->tgid, sock_tag_entry->pid,
			     from_kuid(&init_user_ns, current_fsuid()));
/*
 * This check is needed because tagging from a process that
 * didn't open /dev/xt_qtaguid still adds the sock_tag_entry
 * to sock_tag_tree.
*/
	if (sock_tag_entry->list.next)
		list_del(&sock_tag_entry->list);

	tag_ref_entry->num_sock_tags--;
	if (!sock_tag_entry->pid) {
		/* No process-release will retire a socket-owned tag reference.
		 * Retire zero references now; leave accounting counters intact.
		 */
		free_tag_ref_from_utd_entry(tag_ref_entry, utd_entry);
		put_utd_entry(utd_entry);
	}
	/* Legacy process-owned reference lifetime remains unchanged. */
	spin_unlock_bh(&uid_tag_data_tree_lock);
	spin_unlock_bh(&sock_tag_list_lock);
	/*
	 * Release the sock_fd that was grabbed at tag time.
	 */
	sock_put(sock_tag_entry->sk);
	CT_DEBUG("qtaguid: done. st@%p ...->sk_refcnt=%d\n",
		 sock_tag_entry,
		 atomic_read(&el_socket->sk->sk_refcnt));

	kfree(sock_tag_entry);
	atomic64_inc(&qtu_events.sockets_untagged);

	return 0;
}

static int qtudev_open(struct inode *inode, struct file *file)
{
	struct uid_tag_data *utd_entry;
	struct proc_qtu_data  *pqd_entry;
	struct proc_qtu_data  *new_pqd_entry;
	int res;
	bool utd_entry_found;

	if (unlikely(qtu_proc_handling_passive))
		return 0;

	DR_DEBUG("qtaguid: qtudev_open(): pid=%u tgid=%u uid=%u\n",
		 current->pid, current->tgid, from_kuid(&init_user_ns, current_fsuid()));

	spin_lock_bh(&uid_tag_data_tree_lock);

	/* Look for existing uid data, or alloc one. */
	utd_entry = get_uid_data(from_kuid(&init_user_ns, current_fsuid()), &utd_entry_found);
	if (IS_ERR_OR_NULL(utd_entry)) {
		res = PTR_ERR(utd_entry);
		goto err_unlock;
	}

	/* Look for existing PID based proc_data */
	pqd_entry = proc_qtu_data_tree_search(&proc_qtu_data_tree,
					      current->tgid);
	if (pqd_entry) {
		pr_err("qtaguid: qtudev_open(): %u/%u %u "
		       "%s already opened\n",
		       current->pid, current->tgid, from_kuid(&init_user_ns, current_fsuid()),
		       QTU_DEV_NAME);
		res = -EBUSY;
		goto err_unlock_free_utd;
	}

	new_pqd_entry = kzalloc(sizeof(*new_pqd_entry), GFP_ATOMIC);
	if (!new_pqd_entry) {
		pr_err("qtaguid: qtudev_open(): %u/%u %u: "
		       "proc data alloc failed\n",
		       current->pid, current->tgid, from_kuid(&init_user_ns, current_fsuid()));
		res = -ENOMEM;
		goto err_unlock_free_utd;
	}
	new_pqd_entry->pid = current->tgid;
	INIT_LIST_HEAD(&new_pqd_entry->sock_tag_list);
	new_pqd_entry->parent_tag_data = utd_entry;
	utd_entry->num_pqd++;

	proc_qtu_data_tree_insert(new_pqd_entry,
				  &proc_qtu_data_tree);

	spin_unlock_bh(&uid_tag_data_tree_lock);
	DR_DEBUG("qtaguid: tracking data for uid=%u in pqd=%p\n",
		 from_kuid(&init_user_ns, current_fsuid()), new_pqd_entry);
	file->private_data = new_pqd_entry;
	return 0;

err_unlock_free_utd:
	if (!utd_entry_found) {
		rb_erase(&utd_entry->node, &uid_tag_data_tree);
		kfree(utd_entry);
	}
err_unlock:
	spin_unlock_bh(&uid_tag_data_tree_lock);
	return res;
}

static int qtudev_release(struct inode *inode, struct file *file)
{
	struct proc_qtu_data  *pqd_entry = file->private_data;
	struct uid_tag_data  *utd_entry = pqd_entry->parent_tag_data;
	struct sock_tag *st_entry;
	struct rb_root st_to_free_tree = RB_ROOT;
	struct list_head *entry, *next;
	struct tag_ref *tr;

	if (unlikely(qtu_proc_handling_passive))
		return 0;

	/*
	 * Do not trust the current->pid, it might just be a kworker cleaning
	 * up after a dead proc.
	 */
	DR_DEBUG("qtaguid: qtudev_release(): "
		 "pid=%u tgid=%u uid=%u "
		 "pqd_entry=%p->pid=%u utd_entry=%p->active_tags=%d\n",
		 current->pid, current->tgid, pqd_entry->parent_tag_data->uid,
		 pqd_entry, pqd_entry->pid, utd_entry,
		 utd_entry->num_active_tags);

	spin_lock_bh(&sock_tag_list_lock);
	spin_lock_bh(&uid_tag_data_tree_lock);

	list_for_each_safe(entry, next, &pqd_entry->sock_tag_list) {
		st_entry = list_entry(entry, struct sock_tag, list);
		DR_DEBUG("qtaguid: %s(): "
			 "erase sock_tag=%p->sk=%p pid=%u tgid=%u uid=%u\n",
			 __func__,
			 st_entry, st_entry->sk,
			 current->pid, current->tgid,
			 pqd_entry->parent_tag_data->uid);

		utd_entry = uid_tag_data_tree_search(
			&uid_tag_data_tree,
			get_uid_from_tag(st_entry->tag));
		BUG_ON(IS_ERR_OR_NULL(utd_entry));
		DR_DEBUG("qtaguid: %s(): "
			 "looking for tag=0x%llx in utd_entry=%p\n", __func__,
			 st_entry->tag, utd_entry);
		tr = tag_ref_tree_search(&utd_entry->tag_ref_tree,
					 st_entry->tag);
		BUG_ON(!tr);
		BUG_ON(tr->num_sock_tags <= 0);
		tr->num_sock_tags--;
		free_tag_ref_from_utd_entry(tr, utd_entry);

		rb_erase(&st_entry->sock_node, &sock_tag_tree);
		list_del(&st_entry->list);
		/* Can't sockfd_put() within spinlock, do it later. */
		sock_tag_tree_insert(st_entry, &st_to_free_tree);

		/*
		 * Try to free the utd_entry if no other proc_qtu_data is
		 * using it (num_pqd is 0) and it doesn't have active tags
		 * (num_active_tags is 0).
		 */
		put_utd_entry(utd_entry);
	}

	rb_erase(&pqd_entry->node, &proc_qtu_data_tree);
	BUG_ON(pqd_entry->parent_tag_data->num_pqd < 1);
	pqd_entry->parent_tag_data->num_pqd--;
	put_utd_entry(pqd_entry->parent_tag_data);
	kfree(pqd_entry);
	file->private_data = NULL;

	spin_unlock_bh(&uid_tag_data_tree_lock);
	spin_unlock_bh(&sock_tag_list_lock);


	sock_tag_tree_erase(&st_to_free_tree);

	spin_lock_bh(&sock_tag_list_lock);
	prdebug_full_state_locked(0, "%s(): pid=%u tgid=%u", __func__,
			   current->pid, current->tgid);
	spin_unlock_bh(&sock_tag_list_lock);
	return 0;
}

static long qtudev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct proc_qtu_data *pqd_entry = file->private_data;
	int res = 0;

	if (cmd != QTAGUID_SOCKET_OWNED_SESSION)
		return -ENOTTY;
	if (arg)
		return -EINVAL;
	if (!uid_eq(current_euid(), GLOBAL_ROOT_UID) || !capable(CAP_NET_ADMIN))
		return -EPERM;
	if (module_passive || qtu_proc_handling_passive)
		return -EOPNOTSUPP;

	spin_lock_bh(&sock_tag_list_lock);
	spin_lock_bh(&uid_tag_data_tree_lock);
	if (!pqd_entry || pqd_entry->pid != current->tgid)
		res = -EPERM;
	else if (!list_empty(&pqd_entry->sock_tag_list))
		res = -EBUSY;
	else
		pqd_entry->socket_owned = true;
	spin_unlock_bh(&uid_tag_data_tree_lock);
	spin_unlock_bh(&sock_tag_list_lock);
	return res;
}

static struct tag_counter_set *tag_counter_set_tree_search(struct rb_root *root,
							   tag_t tag)
{
	struct tag_node *node = tag_node_tree_search(root, tag);
	if (!node)
		return NULL;
	return rb_entry(&node->node, struct tag_counter_set, tn.node);

}

static void put_tag_ref_tree(tag_t full_tag, struct uid_tag_data *utd_entry)
{
	struct rb_node *node;
	struct tag_ref *tr_entry;
	tag_t acct_tag;

	DR_DEBUG("qtaguid: %s(tag=0x%llx (uid=%u))\n", __func__,
		 full_tag, get_uid_from_tag(full_tag));
	acct_tag = get_atag_from_tag(full_tag);
	node = rb_first(&utd_entry->tag_ref_tree);
	while (node) {
		tr_entry = rb_entry(node, struct tag_ref, tn.node);
		node = rb_next(node);
		if (!acct_tag || tr_entry->tn.tag == full_tag)
			free_tag_ref_from_utd_entry(tr_entry, utd_entry);
	}
}

static int ctrl_cmd_delete(const char *input)
{
	char cmd;
	int uid_int;
	kuid_t uid;
	uid_t entry_uid;
	tag_t acct_tag;
	tag_t tag;
	int res, argc;
	struct iface_stat *iface_entry;
	struct rb_node *node;
	struct sock_tag *st_entry;
	struct rb_root st_to_free_tree = RB_ROOT;
	struct tag_stat *ts_entry;
	struct tag_counter_set *tcs_entry;
	struct tag_ref *tr_entry;
	struct uid_tag_data *utd_entry;

	argc = sscanf(input, "%c %llu %u", &cmd, &acct_tag, &uid_int);
	uid = make_kuid(&init_user_ns, uid_int);
	CT_DEBUG("qtaguid: ctrl_delete(%s): argc=%d cmd=%c "
		 "user_tag=0x%llx uid=%u\n", input, argc, cmd,
		 acct_tag, uid_int);
	if (argc < 2) {
		res = -EINVAL;
		goto err;
	}
	if (!valid_atag(acct_tag)) {
		pr_info("qtaguid: ctrl_delete(%s): invalid tag\n", input);
		res = -EINVAL;
		goto err;
	}
	if (argc < 3) {
		uid = current_fsuid();
		uid_int = from_kuid(&init_user_ns, uid);
	} else if (!can_impersonate_uid(uid)) {
		pr_info("qtaguid: ctrl_delete(%s): "
			"insufficient priv from pid=%u tgid=%u uid=%u\n",
			input, current->pid, current->tgid, from_kuid(&init_user_ns, current_fsuid()));
		res = -EPERM;
		goto err;
	}

	tag = combine_atag_with_uid(acct_tag, uid_int);
	CT_DEBUG("qtaguid: ctrl_delete(%s): "
		 "looking for tag=0x%llx (uid=%u)\n",
		 input, tag, uid_int);

	/* Delete socket tags */
	spin_lock_bh(&sock_tag_list_lock);
	spin_lock_bh(&uid_tag_data_tree_lock);
	node = rb_first(&sock_tag_tree);
	while (node) {
		st_entry = rb_entry(node, struct sock_tag, sock_node);
		entry_uid = get_uid_from_tag(st_entry->tag);
		node = rb_next(node);
		if (entry_uid != uid_int)
			continue;

		CT_DEBUG("qtaguid: ctrl_delete(%s): st tag=0x%llx (uid=%u)\n",
			 input, st_entry->tag, entry_uid);

		if (!acct_tag || st_entry->tag == tag) {
			rb_erase(&st_entry->sock_node, &sock_tag_tree);
			/* Can't sockfd_put() within spinlock, do it later. */
			sock_tag_tree_insert(st_entry, &st_to_free_tree);
			tr_entry = lookup_tag_ref(st_entry->tag, NULL);
			BUG_ON(tr_entry->num_sock_tags <= 0);
			tr_entry->num_sock_tags--;
			/*
			 * TODO: remove if, and start failing.
			 * This is a hack to work around the fact that in some
			 * places we have "if (IS_ERR_OR_NULL(pqd_entry))"
			 * and are trying to work around apps
			 * that didn't open the /dev/xt_qtaguid.
			 */
			if (st_entry->list.next && st_entry->list.prev)
				list_del(&st_entry->list);
		}
	}
	spin_unlock_bh(&uid_tag_data_tree_lock);
	spin_unlock_bh(&sock_tag_list_lock);

	sock_tag_tree_erase(&st_to_free_tree);

	/* Delete tag counter-sets */
	spin_lock_bh(&tag_counter_set_list_lock);
	/* Counter sets are only on the uid tag, not full tag */
	tcs_entry = tag_counter_set_tree_search(&tag_counter_set_tree, tag);
	if (tcs_entry) {
		CT_DEBUG("qtaguid: ctrl_delete(%s): "
			 "erase tcs: tag=0x%llx (uid=%u) set=%d\n",
			 input,
			 tcs_entry->tn.tag,
			 get_uid_from_tag(tcs_entry->tn.tag),
			 tcs_entry->active_set);
		rb_erase(&tcs_entry->tn.node, &tag_counter_set_tree);
		kfree(tcs_entry);
	}
	spin_unlock_bh(&tag_counter_set_list_lock);

	/*
	 * If acct_tag is 0, then all entries belonging to uid are
	 * erased.
	 */
	spin_lock_bh(&iface_stat_list_lock);
	list_for_each_entry(iface_entry, &iface_stat_list, list) {
		spin_lock_bh(&iface_entry->tag_stat_list_lock);
		node = rb_first(&iface_entry->tag_stat_tree);
		while (node) {
			ts_entry = rb_entry(node, struct tag_stat, tn.node);
			entry_uid = get_uid_from_tag(ts_entry->tn.tag);
			node = rb_next(node);

			CT_DEBUG("qtaguid: ctrl_delete(%s): "
				 "ts tag=0x%llx (uid=%u)\n",
				 input, ts_entry->tn.tag, entry_uid);

			if (entry_uid != uid_int)
				continue;
			if (!acct_tag || ts_entry->tn.tag == tag) {
				CT_DEBUG("qtaguid: ctrl_delete(%s): "
					 "erase ts: %s 0x%llx %u\n",
					 input, iface_entry->ifname,
					 get_atag_from_tag(ts_entry->tn.tag),
					 entry_uid);
				rb_erase(&ts_entry->tn.node,
					 &iface_entry->tag_stat_tree);
				kfree(ts_entry);
			}
		}
		spin_unlock_bh(&iface_entry->tag_stat_list_lock);
	}
	spin_unlock_bh(&iface_stat_list_lock);

	/* Cleanup the uid_tag_data */
	spin_lock_bh(&uid_tag_data_tree_lock);
	node = rb_first(&uid_tag_data_tree);
	while (node) {
		utd_entry = rb_entry(node, struct uid_tag_data, node);
		entry_uid = utd_entry->uid;
		node = rb_next(node);

		CT_DEBUG("qtaguid: ctrl_delete(%s): "
			 "utd uid=%u\n",
			 input, entry_uid);

		if (entry_uid != uid_int)
			continue;
		/*
		 * Go over the tag_refs, and those that don't have
		 * sock_tags using them are freed.
		 */
		put_tag_ref_tree(tag, utd_entry);
		put_utd_entry(utd_entry);
	}
	spin_unlock_bh(&uid_tag_data_tree_lock);

	atomic64_inc(&qtu_events.delete_cmds);
	res = 0;

err:
	return res;
}
static void as(pid_t pid,uid_t uid) { current->pid=current->tgid=pid;current->uid=uid; }
static void tag(int fd,unsigned tag,uid_t uid) { char b[96];snprintf(b,sizeof(b),"t %d %llu %u",fd,(tag_t)tag<<32,uid);CHECK(ctrl_cmd_tag(b)==0); }
static struct file session(pid_t pid,bool owned) { struct file f={0}; as(pid,0);CHECK(qtudev_open(NULL,&f)==0);if(owned)CHECK(qtudev_ioctl(&f,QTAGUID_SOCKET_OWNED_SESSION,0)==0);return f; }
static void release(struct file*f) { CHECK(qtudev_release(NULL,f)==0);CHECK(!f->private_data); }
static void empty(void) { CHECK(!sock_tag_tree.rb_node);CHECK(!uid_tag_data_tree.rb_node);CHECK(!proc_qtu_data_tree.rb_node);CHECK(!allocations);for(int i=0;i<16;++i)CHECK(socks[i].refs==1); }
static int previous_socket_owned_tests(void) {
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
return 0;
}

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
