#pragma once
#include <stdbool.h>
#include <stddef.h>
#define NFPROTO_UNSPEC 0
#define XTABLES_VERSION "fixture"
#define XT_ALIGN(x) (((x)+7)&~7)
#define XTTYPE_STRING 1
#define XTOPT_MAND 1
#define XTOPT_TABLEEND {0}
#define PARAMETER_PROBLEM 2
struct xt_entry_match{unsigned char data[64];};
struct xt_option_entry{const char*name;unsigned id,type,flags;};
struct xt_option_call{const char*arg;const struct xt_option_entry*entry;void*data;unsigned xflags;bool invert;};
struct xtables_match{unsigned family;const char*name;unsigned revision;const char*version;size_t size,userspacesize;void(*help)(void);void(*init)(struct xt_entry_match*);void(*print)(const void*,const struct xt_entry_match*,int);void(*save)(const void*,const struct xt_entry_match*);void(*x6_parse)(struct xt_option_call*);const struct xt_option_entry*x6_options;};
void xtables_option_parse(struct xt_option_call*);
__attribute__((noreturn,format(printf,2,3))) void xtables_error(unsigned,const char*,...);
void xtables_register_match(struct xtables_match*);
