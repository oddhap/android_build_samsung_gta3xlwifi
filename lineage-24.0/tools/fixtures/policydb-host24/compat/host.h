#ifndef HOST_FIXTURE_H
#define HOST_FIXTURE_H
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
typedef _Bool bool;
#define true 1
#define false 0
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef int8_t s8;typedef int16_t s16;typedef int32_t s32;typedef int64_t s64;
typedef u16 __le16;typedef u32 __le32;typedef u64 __le64;typedef u32 __be32;
typedef u32 __u32;typedef u16 __u16;typedef u64 __u64;
typedef unsigned gfp_t;typedef int spinlock_t;
#define CONFIG_64BIT 1
#define BITS_PER_LONG 64
#define __packed __attribute__((packed))
#define __init
#define __exit
#define __read_mostly
#define __rcu
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define __GFP_ZERO 1
#define __GFP_NOWARN 0
#define SLAB_PANIC 0
#define SLAB_HWCACHE_ALIGN 0
#define KERN_ERR ""
#define KERN_INFO ""
#define KERN_WARNING ""
#define SELINUX_MAGIC 0xf97cff8cU
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BUG() abort()
#define KERN_DEBUG ""
#define BUG_ON(x) assert(!(x))
#define WARN_ON(x) (!!(x))
#define likely(x) (x)
#define unlikely(x) (x)
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define roundup(x,y) (((x)+(y)-1)/(y)*(y))
#define rounddown(x,y) ((x)/(y)*(y))
#define cond_resched() ((void)0)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
static inline int host_printk(const char *fmt, ...){char copy[2048];size_t n=strlen(fmt);assert(n<sizeof(copy));memcpy(copy,fmt,n+1);for(size_t i=0;i+1<n;i++)if(copy[i]=='%'&&copy[i+1]=='Z')copy[i+1]='z';va_list ap;va_start(ap,fmt);int rc=vfprintf(stderr,copy,ap);va_end(ap);return rc;}
#define printk host_printk
_Noreturn static inline void panic(const char *fmt, ...){fprintf(stderr,"PANIC: %s\n",fmt);_Exit(77);}
#define pr_info(...) fprintf(stderr,__VA_ARGS__)
#define pr_err(...) fprintf(stderr,__VA_ARGS__)
#define pr_warn(...) fprintf(stderr,__VA_ARGS__)
static inline void *kmalloc(size_t n,gfp_t g){(void)g;return malloc(n);}
static inline void *kzalloc(size_t n,gfp_t g){(void)g;return calloc(1,n);}
static inline void *kcalloc(size_t n,size_t s,gfp_t g){(void)g;return calloc(n,s);}
static inline void *kmalloc_array(size_t n,size_t s,gfp_t g){(void)g;if(s && n>SIZE_MAX/s)return NULL;return malloc(n*s);}
static inline void kfree(const void *p){free((void *)p);}
#define kstrdup(s,g) strdup(s)
struct kmem_cache {size_t size;};
static inline struct kmem_cache *kmem_cache_create(const char *name,size_t n,size_t align,unsigned flags,void (*ctor)(void *)){(void)name;(void)align;(void)flags;assert(!ctor);struct kmem_cache *c=malloc(sizeof(*c));assert(c);c->size=n;return c;}
static inline void *kmem_cache_zalloc(struct kmem_cache *c,gfp_t g){return kzalloc(c->size,g);}
static inline void *kmem_cache_alloc(struct kmem_cache *c,gfp_t g){return kmalloc(c->size,g);}
static inline void kmem_cache_free(struct kmem_cache *c,void *p){(void)c;free(p);}
static inline void kmem_cache_destroy(struct kmem_cache *c){free(c);}
static inline unsigned find_next_bit(const unsigned long *p,unsigned n,unsigned start){for(unsigned i=start;i<n;i++)if((p[i/64]>>(i%64))&1UL)return i;return n;}
static inline unsigned find_first_bit(const unsigned long *p,unsigned n){return find_next_bit(p,n,0);}
static inline unsigned hweight_long(unsigned long v){return __builtin_popcountl(v);}
static inline unsigned fls(unsigned v){return v?32-__builtin_clz(v):0;}
static inline unsigned long __fls(unsigned long v){assert(v);return 63-__builtin_clzl(v);}
static inline unsigned fls64(uint64_t v){return v?64-__builtin_clzll(v):0;}
static inline unsigned long partial_name_hash(unsigned long c,unsigned long hash){return (hash+(c<<4)+(c>>4))*11;}
struct qstr {const unsigned char *name;unsigned len;};struct super_block;struct netlbl_lsm_catmap;struct netlbl_lsm_secattr;
struct flex_array {size_t element_size,total_nr_elements;unsigned char *bytes;};
static inline struct flex_array *flex_array_alloc(int size,unsigned n,gfp_t flags){(void)flags;struct flex_array *a=malloc(sizeof(*a));if(!a)return NULL;a->element_size=size;a->total_nr_elements=n;a->bytes=calloc(n?n:1,size);if(!a->bytes){free(a);return NULL;}return a;}
static inline void *flex_array_get(struct flex_array *a,unsigned i){if(i>=a->total_nr_elements)return NULL;return a->bytes+i*a->element_size;}
static inline void *flex_array_get_ptr(struct flex_array *a,unsigned i){void **p=flex_array_get(a,i);return p?*p:NULL;}
static inline int flex_array_put_ptr(struct flex_array *a,unsigned i,void *v,gfp_t g){(void)g;void **p=flex_array_get(a,i);if(!p)return -ENOSPC;*p=v;return 0;}
static inline int flex_array_prealloc(struct flex_array *a,unsigned start,unsigned n,gfp_t g){(void)g;return start<=a->total_nr_elements&&n<=a->total_nr_elements-start?0:-ENOSPC;}
static inline void flex_array_free(struct flex_array *a){free(a->bytes);free(a);}
#endif
