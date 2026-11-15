#include <linux/netfilter/gta3xlwifi_iface_stats.h>
#include <linux/netfilter/gta3xlwifi_packet_stats.h>
static_assert(sizeof(gta3xlwifi_iface_name_entry)==20);
static_assert(sizeof(gta3xlwifi_iface_names_transfer)==32);
static_assert(__builtin_offsetof(gta3xlwifi_iface_names_transfer,entries)==8);
static_assert(GTA3XLWIFI_IFACE_NAMES_GET==0xc0206762U);
static_assert(GTA3XLWIFI_UID_CAP_IFACE_NAMES==65536U);static_assert(sizeof(gta3xlwifi_uid_cleanup)==64);static_assert(GTA3XLWIFI_UID_CLEANUP==0xc0406763U);
extern "C" unsigned ifname_wire_size(){return sizeof(gta3xlwifi_iface_name_entry); }
