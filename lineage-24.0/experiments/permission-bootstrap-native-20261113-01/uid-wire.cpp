#include <linux/netfilter/gta3xlwifi_packet_stats.h>
static_assert(sizeof(gta3xlwifi_stats_key)==16);
static_assert(sizeof(gta3xlwifi_packet_stats_entry)==48);
static_assert(sizeof(gta3xlwifi_app_stats_entry)==40);
static_assert(sizeof(gta3xlwifi_packet_stats_state)==88);
static_assert(sizeof(gta3xlwifi_packet_stats_transfer)==48);
static_assert(sizeof(gta3xlwifi_packet_stats_swap)==32);
static_assert(sizeof(gta3xlwifi_packet_stats_ack)==24);
static_assert(sizeof(gta3xlwifi_packet_stats_edit)==24);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_entry,rx_packets)==16);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_entry,tx_bytes)==40);
static_assert(__builtin_offsetof(gta3xlwifi_app_stats_entry,rx_packets)==8);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_state,active_epoch)==8);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_state,bank_epoch)==32);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_state,total_stats_lost)==72);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_transfer,epoch)==8);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_transfer,entries)==24);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_transfer,sequence)==40);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_swap,inactive_epoch)==24);
static_assert(__builtin_offsetof(gta3xlwifi_packet_stats_ack,epoch)==8);
static_assert(GTA3XLWIFI_STATS_GET_STATE==0x8058675b);
static_assert(GTA3XLWIFI_STATS_READ==0xc030675c);
static_assert(GTA3XLWIFI_STATS_SWAP==0xc020675d);
static_assert(GTA3XLWIFI_STATS_ACK==0x4018675e);
static_assert(GTA3XLWIFI_STATS_EDIT==0x4018675f);
extern "C" unsigned packet_stats_wire_size(){return sizeof(gta3xlwifi_packet_stats_transfer);}
