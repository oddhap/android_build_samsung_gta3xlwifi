#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "/srv/android/ports/lineage-24.0-arm64/kernel-packet-hooks-20261113-02/src/include/uapi/linux/netfilter/gta3xlwifi_iface_stats.h"
typedef uint32_t u32;
#define READ_ONCE(x) (x)
static bool gta3xlwifi_iface_registered;
u32 gta3xlwifi_iface_egress_features(void)
{
#if defined(CONFIG_INET) && defined(CONFIG_IPV6)
    return GTA3XLWIFI_UID_CAP_IFACE_DROP_UNDO;
#else
    return 0;
#endif
}
u32 gta3xlwifi_iface_stats_features(void)
{
    return READ_ONCE(gta3xlwifi_iface_registered)?
        GTA3XLWIFI_UID_CAP_IFACE_STATS|gta3xlwifi_iface_egress_features():0;
}
int main(void){
#ifdef BOTH_ENABLED
 unsigned expected=GTA3XLWIFI_UID_CAP_IFACE_DROP_UNDO;
#else
 unsigned expected=0;
#endif
 assert(gta3xlwifi_iface_egress_features()==expected);
 assert(gta3xlwifi_iface_stats_features()==0);
 gta3xlwifi_iface_registered=true;
 assert(gta3xlwifi_iface_stats_features()==(GTA3XLWIFI_UID_CAP_IFACE_STATS|expected));
 puts("passed_cases=3");
}
