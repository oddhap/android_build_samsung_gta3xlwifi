#include <linux/netfilter/gta3xlwifi_local_network.h>
static_assert(sizeof(gta3xlwifi_lna_transfer)==40);
static_assert(__builtin_offsetof(gta3xlwifi_lna_transfer,revision)==16);
static_assert(__builtin_offsetof(gta3xlwifi_lna_transfer,network_entries)==24);
static_assert(__builtin_offsetof(gta3xlwifi_lna_transfer,host_entries)==32);
static_assert(sizeof(gta3xlwifi_lna_entry)==32);
static_assert(__builtin_offsetof(gta3xlwifi_lna_entry,allowed)==28);
static_assert(sizeof(gta3xlwifi_lna_match)==4);
static_assert(GTA3XLWIFI_LNA_SET_IMAGE==0x40286757);
static_assert(GTA3XLWIFI_LNA_GET_IMAGE==0xc0286758);
extern "C" unsigned lna_wire_size(){return sizeof(gta3xlwifi_lna_transfer);}
