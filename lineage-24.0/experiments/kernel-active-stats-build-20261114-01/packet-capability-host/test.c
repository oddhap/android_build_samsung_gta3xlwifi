#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "/srv/android/ports/lineage-24.0-arm64/kernel-packet-capability-20261113-01/src/include/uapi/linux/netfilter/gta3xlwifi_packet_stats.h"
typedef uint32_t u32;
u32 gta3xlwifi_packet_hooks_features(void)
{
#if defined(CONFIG_INET) && defined(CONFIG_IPV6)
    /* This staged source includes both real packet producer bodies and the
     * original full-socket receive/output call sites. Their actual compiled
     * reachability is a mandatory build check, not a BPF/runtime Ready claim.
     */
    return GTA3XLWIFI_UID_CAP_PACKET_STATS_HOOKS;
#else
    return 0;
#endif
}
u32 gta3xlwifi_packet_stats_features(void)
{
#if defined(CONFIG_INET) && defined(CONFIG_IPV6)
    return GTA3XLWIFI_UID_CAP_PACKET_STATS_STORE;
#else
    return 0;
#endif
}
int main(void){
#ifdef BOTH_ENABLED
 assert(gta3xlwifi_packet_hooks_features()==8192);
 assert(gta3xlwifi_packet_stats_features()==4096);
#else
 assert(gta3xlwifi_packet_hooks_features()==0);
 assert(gta3xlwifi_packet_stats_features()==0);
#endif
 puts("passed_cases=2");return 0;
}
