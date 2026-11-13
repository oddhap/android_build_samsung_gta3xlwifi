#include <linux/netfilter/gta3xlwifi_iface_stats.h>
static_assert(sizeof(gta3xlwifi_iface_stats_match)==8);
static_assert(sizeof(gta3xlwifi_iface_stats_entry)==40);
static_assert(sizeof(gta3xlwifi_iface_stats_transfer)==32);
static_assert(__builtin_offsetof(gta3xlwifi_iface_stats_entry,rx_packets)==8);
static_assert(__builtin_offsetof(gta3xlwifi_iface_stats_entry,tx_bytes)==32);
static_assert(__builtin_offsetof(gta3xlwifi_iface_stats_transfer,entries)==8);
static_assert(__builtin_offsetof(gta3xlwifi_iface_stats_transfer,lost_updates)==16);
static_assert(__builtin_offsetof(gta3xlwifi_iface_stats_transfer,update_sequence)==24);
static_assert(GTA3XLWIFI_IFACE_STATS_GET==0xc020675a);
extern "C" unsigned iface_wire_size(){return sizeof(gta3xlwifi_iface_stats_transfer);}
