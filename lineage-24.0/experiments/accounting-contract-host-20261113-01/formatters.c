#include <stdint.h>
#include <stdio.h>
#include <string.h>
struct xt_mark_tginfo2{uint32_t mark,mask;};struct xt_entry_target{_Alignas(8) unsigned char data[8];};struct xt_policy_info{unsigned flags;};
#define XT_POLICY_MATCH_IN 1
#define XT_POLICY_MATCH_OUT 2
#define XT_POLICY_MATCH_NONE 4
#define XT_POLICY_MATCH_STRICT 8
static void mark_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_mark_tginfo2 *info = (const void *)target->data;

	printf(" --set-xmark 0x%x/0x%x", info->mark, info->mask);
}
static void print_flags(const char *prefix, const struct xt_policy_info *info)
{
	if (info->flags & XT_POLICY_MATCH_IN)
		printf(" %sdir in", prefix);
	else
		printf(" %sdir out", prefix);

	if (info->flags & XT_POLICY_MATCH_NONE)
		printf(" %spol none", prefix);
	else
		printf(" %spol ipsec", prefix);

	if (info->flags & XT_POLICY_MATCH_STRICT)
		printf(" %sstrict", prefix);
}
int main(void){struct xt_entry_target t;struct xt_mark_tginfo2*info=(void*)t.data;info->mark=0x100000;info->mask=0x100000;printf("-j MARK");mark_tg_save(NULL,&t);puts("");info->mark=0;printf("-j MARK");mark_tg_save(NULL,&t);puts("");struct xt_policy_info p={XT_POLICY_MATCH_IN};printf("-m policy");print_flags("--",&p);puts("");p.flags=XT_POLICY_MATCH_OUT;printf("-m policy");print_flags("--",&p);puts("");}
