#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include "/srv/android/ports/lineage-24.0-arm64/kernel-socket-capability-20261112-01/src/include/uapi/linux/netfilter/gta3xlwifi_socket_tables.h"
typedef uint32_t u32;
#define IS_ENABLED(x) (x)
#define CONFIG_IP6_NF_IPTABLES 0
#define smp_load_acquire(p) (*(p))
static bool socket_tables_registered;
u32 gta3xlwifi_socket_tables_features(void)
{
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    return smp_load_acquire(&socket_tables_registered) ?
        GTA3XLWIFI_UID_CAP_SOCKET_TABLES : 0;
#else
    return 0;
#endif
}
int main(void){socket_tables_registered=false;assert(gta3xlwifi_socket_tables_features()==0);socket_tables_registered=true;assert(gta3xlwifi_socket_tables_features()==0);return 0;}
