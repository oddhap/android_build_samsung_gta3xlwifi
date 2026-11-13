
#include <cassert>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include "Fwmark.h"
#include "mainline/XtBpfProgLocations.h"
static std::string StringPrintf(const char*format,...){va_list v;va_start(v,format);va_list copy;va_copy(copy,v);int n=vsnprintf(nullptr,0,format,copy);va_end(copy);assert(n>=0);std::vector<char> text(n+1);assert(vsnprintf(text.data(),text.size(),format,v)==n);va_end(v);return std::string(text.data(),n);}
static uint32_t uidBillingMask=Fwmark::getUidBillingMask();
#define IPSEC_IFACE_PREFIX "ipsec"
static uint32_t CLAT_MARK=0xdeadc1a7u;
const std::string COMMIT_AND_CLOSE = "COMMIT\n";
std::vector<std::string> getBasicAccountingCommands() {
    // clang-format off
    std::vector<std::string> ipt_basic_accounting_commands = {
            "*filter",

            "-A bw_INPUT -j bw_global_alert",
            // Prevents IPSec double counting (ESP and UDP-encap-ESP respectively)
            "-A bw_INPUT -p esp -j RETURN",
            StringPrintf("-A bw_INPUT -m mark --mark 0x%x/0x%x -j RETURN", uidBillingMask,
                         uidBillingMask),
            StringPrintf("-A bw_INPUT -j MARK --or-mark 0x%x", uidBillingMask),
            "-A bw_OUTPUT -j bw_global_alert",
            "-A bw_costly_shared -j bw_penalty_box",
            ("-I bw_penalty_box -m bpf --object-pinned " XT_BPF_DENYLIST_PROG_PATH " -j REJECT"),
            "-A bw_penalty_box -j bw_happy_box",
            "-A bw_happy_box -j bw_data_saver",
            "-A bw_data_saver -j RETURN",
            ("-I bw_happy_box -m bpf --object-pinned " XT_BPF_ALLOWLIST_PROG_PATH " -j RETURN"),
            "COMMIT",

            "*raw",
            // Drop duplicate ingress clat packets
            StringPrintf("-A bw_raw_PREROUTING -m mark --mark 0x%x -j DROP", CLAT_MARK),
            // Prevents IPSec double counting (Tunnel mode and Transport mode,
            // respectively)
            ("-A bw_raw_PREROUTING -i " IPSEC_IFACE_PREFIX "+ -j RETURN"),
            "-A bw_raw_PREROUTING -m policy --pol ipsec --dir in -j RETURN",
            // This is ingress interface accounting. There is no need to do anything specific
            // for 464xlat here, because we only ever account 464xlat traffic on the clat
            // interface and later correct for overhead (+20 bytes/packet).
            //
            // Note: eBPF offloaded packets never hit base interface's ip6tables, and non
            // offloaded packets are dropped up above due to being marked with CLAT_MARK
            //
            // Hence we will never double count and additional corrections are not needed.
            // We can simply take the sum of base and stacked (+20B/pkt) interface counts.
            ("-A bw_raw_PREROUTING -m bpf --object-pinned " XT_BPF_INGRESS_PROG_PATH),
            "COMMIT",

            "*mangle",
            // Prevents IPSec double counting (Tunnel mode and Transport mode,
            // respectively)
            ("-A bw_mangle_POSTROUTING -o " IPSEC_IFACE_PREFIX "+ -j RETURN"),
            "-A bw_mangle_POSTROUTING -m policy --pol ipsec --dir out -j RETURN",
            // Clear the uid billing done (egress) mark before sending this packet
            StringPrintf("-A bw_mangle_POSTROUTING -j MARK --set-mark 0x0/0x%x", uidBillingMask),
            // This is egress interface accounting: we account 464xlat traffic only on
            // the clat interface (as offloaded packets never hit base interface's ip6tables)
            // and later sum base and stacked with overhead (+20B/pkt) in higher layers
            ("-A bw_mangle_POSTROUTING -m bpf --object-pinned " XT_BPF_EGRESS_PROG_PATH),
            COMMIT_AND_CLOSE};
    // clang-format on
    return ipt_basic_accounting_commands;
}
std::vector<std::string> getGta3xlwifiBasicAccountingCommands() {
    // clang-format off
    std::vector<std::string> ipt_basic_accounting_commands = {
            "*filter",

            "-A bw_INPUT -j bw_global_alert",
            // Prevents IPSec double counting (ESP and UDP-encap-ESP respectively)
            "-A bw_INPUT -p esp -j RETURN",
            StringPrintf("-A bw_INPUT -m mark --mark 0x%x/0x%x -j RETURN", uidBillingMask,
                         uidBillingMask),
            StringPrintf("-A bw_INPUT -j MARK --or-mark 0x%x", uidBillingMask),
            "-A bw_OUTPUT -j bw_global_alert",
            "-A bw_costly_shared -j bw_penalty_box",
            // MeteredRoots initializes EMPTY penalty/happy parents under HOLD.
            // Data-saver control goes through SocketPolicyProjection; this old
            // chain is retained for source compatibility, outside its new path.
            "-A bw_data_saver -j RETURN",
            "COMMIT",

            "*raw",
            // Drop duplicate ingress clat packets
            StringPrintf("-A bw_raw_PREROUTING -m mark --mark 0x%x -j DROP", CLAT_MARK),
            // Prevents IPSec double counting (Tunnel mode and Transport mode,
            // respectively)
            ("-A bw_raw_PREROUTING -i " IPSEC_IFACE_PREFIX "+ -j RETURN"),
            "-A bw_raw_PREROUTING -m policy --pol ipsec --dir in -j RETURN",
            // This is ingress interface accounting. There is no need to do anything specific
            // for 464xlat here, because we only ever account 464xlat traffic on the clat
            // interface and later correct for overhead (+20 bytes/packet).
            //
            // Note: eBPF offloaded packets never hit base interface's ip6tables, and non
            // offloaded packets are dropped up above due to being marked with CLAT_MARK
            //
            // Hence we will never double count and additional corrections are not needed.
            // We can simply take the sum of base and stacked (+20B/pkt) interface counts.
            "-A bw_raw_PREROUTING -m gta3xlwifi_iface_stats --direction ingress",
            "COMMIT",

            "*mangle",
            // Prevents IPSec double counting (Tunnel mode and Transport mode,
            // respectively)
            ("-A bw_mangle_POSTROUTING -o " IPSEC_IFACE_PREFIX "+ -j RETURN"),
            "-A bw_mangle_POSTROUTING -m policy --pol ipsec --dir out -j RETURN",
            // Clear the uid billing done (egress) mark before sending this packet
            StringPrintf("-A bw_mangle_POSTROUTING -j MARK --set-mark 0x0/0x%x", uidBillingMask),
            // This is egress interface accounting: we account 464xlat traffic only on
            // the clat interface (as offloaded packets never hit base interface's ip6tables)
            // and later sum base and stacked with overhead (+20B/pkt) in higher layers
            "-A bw_mangle_POSTROUTING -m gta3xlwifi_iface_stats --direction egress",
            COMMIT_AND_CLOSE};
    // clang-format on
    return ipt_basic_accounting_commands;
}
struct BandwidthController{static std::vector<std::string> makeGta3xlwifiAccountingCommands();};
std::vector<std::string> BandwidthController::makeGta3xlwifiAccountingCommands() {
    return getGta3xlwifiBasicAccountingCommands();
}

int main(){for(const auto&row:BandwidthController::makeGta3xlwifiAccountingCommands()){for(unsigned char c:row)printf("%02x",c);puts("");}}
