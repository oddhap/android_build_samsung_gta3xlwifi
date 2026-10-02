#!/usr/bin/env python3
"""Apply the SM-T510 iptables networking port to pinned LineageOS 21 sources.

Run with the build stopped. This implementation never substitutes successful
no-ops for firewall operations: mutations call netd and propagate failures.
"""
from pathlib import Path
import shutil, subprocess
ROOT = Path('/srv/android')
TOP = ROOT/'src/lineage-21.0'
PORT = ROOT/'ports/lineage-21'
PROJECTS = {
    'packages/modules/DnsResolver': 'fe72ac15ad7f0428e662415458cc51e03746e33e',
    'system/netd': 'dbc81b7c46cc59f761c0ac5e390f3fc71dfa7b40',
    'system/bpf': 'd5e515c0085b354fb8f00ef3feb09ec0f0b1f60b',
    'packages/modules/Connectivity': '965d387f90f22d20c3cba4dc90fd900f2e1b7ed0',
}
for project, revision in PROJECTS.items():
    actual = subprocess.check_output(['git','-C',str(TOP/project),'rev-parse','HEAD'],text=True).strip()
    if actual != revision: raise SystemExit(f'Review changed project revision: {project} {actual}')

def edit(rel, before, after):
    p=TOP/rel; s=p.read_text()
    if after in s: return
    if s.count(before) != 1: raise SystemExit(f'Expected one source anchor: {rel}: {before[:100]}')
    p.write_text(s.replace(before, after))

N='system/netd/server/'
C='packages/modules/Connectivity/'
for p in (PORT/'compat/netd').iterdir(): shutil.copy2(p,TOP/N/p.name)
shutil.copy2(PORT/'compat/connectivity/Gta3xlwifiLegacyNetworkRules.java',
            TOP/C/'service/src/com/android/server/Gta3xlwifiLegacyNetworkRules.java')
edit(N+'Android.bp', '        "BandwidthController.cpp",',
     '        "BandwidthController.cpp",\n        "Gta3xlwifiLegacyFirewall.cpp",')
edit(N+'Android.bp','    name: "netd",', '''    name: "netd",
    ldflags: [
        "-Wl,--export-dynamic-symbol=gta3xlwifi_legacy_is_uid_networking_blocked",
        "-Wl,--export-dynamic-symbol=gta3xlwifi_legacy_has_stats_permission",
    ],''')
edit(N+'NetdNativeService.cpp', '#include "Controllers.h"',
     '#include "Controllers.h"\n#include "Gta3xlwifiLegacyFirewall.h"')
# Restore the old INetd operations only for the product that opts in.
fn = {
'''binder::Status NetdNativeService::firewallReplaceUidChain(const std::string&, bool,
                                                          const std::vector<int32_t>&, bool*) {
    DEPRECATED;
}''': '''binder::Status NetdNativeService::firewallReplaceUidChain(const std::string& name, bool list,
                                                          const std::vector<int32_t>& uids, bool* ret) {
    if (!::android::net::Gta3xlwifiLegacyFirewall::enabled()) { DEPRECATED; }
    NETD_BIG_LOCK_RPC(PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK);
    int res = Gta3xlwifiLegacyFirewall::get().replaceChain(name, list, uids);
    *ret = (res == 0);
    return statusFromErrcode(res);
}''',
'''binder::Status NetdNativeService::trafficSetNetPermForUids(int32_t, const std::vector<int32_t>&) {
    DEPRECATED;
}''': '''binder::Status NetdNativeService::trafficSetNetPermForUids(int32_t permissions, const std::vector<int32_t>& uids) {
    if (!::android::net::Gta3xlwifiLegacyFirewall::enabled()) { DEPRECATED; }
    NETD_BIG_LOCK_RPC(PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK);
    Gta3xlwifiLegacyFirewall::get().setPermissions(permissions, uids);
    return binder::Status::ok();
}''',
'''binder::Status NetdNativeService::firewallSetUidRule(int32_t, int32_t, int32_t) {
    DEPRECATED;
}''': '''binder::Status NetdNativeService::firewallSetUidRule(int32_t chain, int32_t uid, int32_t rule) {
    if (!::android::net::Gta3xlwifiLegacyFirewall::enabled()) { DEPRECATED; }
    NETD_BIG_LOCK_RPC(PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK);
    if (chain == INetd::FIREWALL_CHAIN_NONE) {
        std::lock_guard firewallGuard(gCtls->firewallCtrl.lock);
        return statusFromErrcode(gCtls->firewallCtrl.setUidRule(NONE, uid, static_cast<FirewallRule>(rule)));
    }
    return statusFromErrcode(Gta3xlwifiLegacyFirewall::get().setUidRule(chain, uid, rule));
}''',
'''binder::Status NetdNativeService::firewallEnableChildChain(int32_t, bool) {
    DEPRECATED;
}''': '''binder::Status NetdNativeService::firewallEnableChildChain(int32_t chain, bool enable) {
    if (!::android::net::Gta3xlwifiLegacyFirewall::enabled()) { DEPRECATED; }
    NETD_BIG_LOCK_RPC(PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK);
    return statusFromErrcode(Gta3xlwifiLegacyFirewall::get().enableChain(chain, enable));
}''',
'''binder::Status NetdNativeService::firewallAddUidInterfaceRules(const std::string&,
                                                               const std::vector<int32_t>&) {
    DEPRECATED;
}''': '''binder::Status NetdNativeService::firewallAddUidInterfaceRules(const std::string& iface,
                                                               const std::vector<int32_t>& uids) {
    if (!::android::net::Gta3xlwifiLegacyFirewall::enabled()) { DEPRECATED; }
    NETD_BIG_LOCK_RPC(PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK);
    return statusFromErrcode(Gta3xlwifiLegacyFirewall::get().setInterfaceRules(iface, uids));
}''',
'''binder::Status NetdNativeService::firewallRemoveUidInterfaceRules(const std::vector<int32_t>&) {
    DEPRECATED;
}''': '''binder::Status NetdNativeService::firewallRemoveUidInterfaceRules(const std::vector<int32_t>& uids) {
    if (!::android::net::Gta3xlwifiLegacyFirewall::enabled()) { DEPRECATED; }
    NETD_BIG_LOCK_RPC(PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK);
    return statusFromErrcode(Gta3xlwifiLegacyFirewall::get().removeInterfaceRules(uids));
}''',
}
for kind,nice,add in [('AddNaughty',False,True),('RemoveNaughty',False,False),('AddNice',True,True),('RemoveNice',True,False)]:
    before=f'binder::Status NetdNativeService::bandwidth{kind}App(int32_t) {{\n    DEPRECATED;\n}}'
    after=f'''binder::Status NetdNativeService::bandwidth{kind}App(int32_t uid) {{
    if (!::android::net::Gta3xlwifiLegacyFirewall::enabled()) {{ DEPRECATED; }}
    NETD_BIG_LOCK_RPC(PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK);
    return statusFromErrcode(Gta3xlwifiLegacyFirewall::get().setMeteredUid(uid, {str(nice).lower()}, {str(add).lower()}));
}}'''
    fn[before]=after
for a,b in fn.items(): edit(N+'NetdNativeService.cpp',a,b)
edit(N+'NetdNativeService.cpp', '''binder::Status NetdNativeService::bandwidthEnableDataSaver(bool enable, bool *ret) {
    NETD_LOCKING_RPC(gCtls->bandwidthCtrl.lock, PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK);
    int err = gCtls->bandwidthCtrl.enableDataSaver(enable);
    *ret = (err == 0);''', '''binder::Status NetdNativeService::bandwidthEnableDataSaver(bool enable, bool *ret) {
    NETD_BIG_LOCK_RPC(PERM_NETWORK_STACK, PERM_MAINLINE_NETWORK_STACK);
    std::lock_guard bandwidthGuard(gCtls->bandwidthCtrl.lock);
    int err = gCtls->bandwidthCtrl.enableDataSaver(enable);
    if (!err && Gta3xlwifiLegacyFirewall::enabled())
        Gta3xlwifiLegacyFirewall::get().setDataSaverState(enable);
    *ret = (err == 0);''')
edit(N+'BandwidthController.cpp','#include "BandwidthController.h"',
     '#include "BandwidthController.h"\n#include "Gta3xlwifiLegacyFirewall.h"')
# Replace only the accounting BPF hooks, retaining quota and bandwidth enforcement.
edit(N+'BandwidthController.cpp', '''    return ipt_basic_accounting_commands;
}''', '''    if (::android::net::Gta3xlwifiLegacyFirewall::enabled()) {
        // Preserve qtaguid's separate UID and interface accounting hooks, with
        // the working pre-BPF IPsec/CLAT exemptions to prevent double counting.
        return {
            "*filter",
            "-A bw_INPUT -j bw_global_alert",
            "-A bw_INPUT -p esp -j RETURN",
            StringPrintf("-A bw_INPUT -m mark --mark 0x%x/0x%x -j RETURN", uidBillingMask, uidBillingMask),
            "-A bw_INPUT -m owner --socket-exists",
            StringPrintf("-A bw_INPUT -j MARK --or-mark 0x%x", uidBillingMask),
            "-A bw_OUTPUT -j bw_global_alert",
            "-A bw_OUTPUT -o " IPSEC_IFACE_PREFIX "+ -j RETURN",
            "-A bw_OUTPUT -m policy --pol ipsec --dir out -j RETURN",
            "-A bw_OUTPUT -m owner --uid-owner clat -j RETURN",
            "-A bw_OUTPUT -m owner --socket-exists",
            "-A bw_costly_shared -j bw_penalty_box",
            "-A bw_penalty_box -j bw_happy_box",
            "-A bw_happy_box -j bw_data_saver",
            "-A bw_data_saver -j RETURN",
            "-I bw_happy_box -m owner --uid-owner 0-9999 -j RETURN",
            "COMMIT",
            "*raw",
            "-A bw_raw_PREROUTING -i " IPSEC_IFACE_PREFIX "+ -j RETURN",
            "-A bw_raw_PREROUTING -m policy --pol ipsec --dir in -j RETURN",
            "-A bw_raw_PREROUTING -m owner --socket-exists",
            "COMMIT",
            "*mangle",
            "-A bw_mangle_POSTROUTING -o " IPSEC_IFACE_PREFIX "+ -j RETURN",
            "-A bw_mangle_POSTROUTING -m policy --pol ipsec --dir out -j RETURN",
            StringPrintf("-A bw_mangle_POSTROUTING -j MARK --set-mark 0x0/0x%x", uidBillingMask),
            "-A bw_mangle_POSTROUTING -m owner --uid-owner clat -j RETURN",
            "-A bw_mangle_POSTROUTING -m owner --socket-exists",
            COMMIT_AND_CLOSE,
        };
    }
    return ipt_basic_accounting_commands;
}''')
edit(N+'main.cpp','#include "Controllers.h"',
     '#include "Controllers.h"\n#include "Gta3xlwifiLegacyFirewall.h"')
edit(N+'main.cpp', '''    if (!CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &cg2_path)) {''',
     '''    if (!CgroupGetControllerPath(CGROUPV2_HIERARCHY_NAME, &cg2_path) &&
        !::android::net::Gta3xlwifiLegacyFirewall::enabled()) {''')
# The BPF loaders explicitly select the installed legacy backend. All other
# devices keep fatal failures and mandatory program loading.
for rel, anchor in [('system/bpf/bpfloader/BpfLoader.cpp','    // Create all the pin subdirectories'),
                    (C+'netbpfload/NetBpfLoad.cpp','    ALOGI("NetBpfLoad \'%s\' starting...", argv[0]);')]:
    edit(rel,anchor,'''    if (android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
        ALOGI("SM-T510 uses the iptables/qtaguid networking backend");
        return android::base::SetProperty("bpf.progs_loaded", "1") ? 0 : 1;
    }

'''+anchor)
# Netd's updatable socket tagging implementation still validates cross-UID
# access and uses the kernel's original qtaguid control ABI.
edit(C+'netd/NetdUpdatable.cpp','#include <android-base/logging.h>',
'''#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
extern "C" int ADnsHelper_setLegacyCallback(bool (*blocked)(uid_t, bool));
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>''')
edit(C+'netd/NetdUpdatable.cpp','static android::net::BpfHandler sBpfHandler;',
'''static android::net::BpfHandler sBpfHandler;
static int sLegacyProcessFd = -1;
static bool (*sLegacyStatsPermission)(uid_t) = nullptr;
static bool (*sLegacyUidBlocked)(uid_t, bool) = nullptr;
extern "C" int libnetd_updatable_setLegacyCallbacks(bool (*blocked)(uid_t, bool), bool (*permission)(uid_t)) {
    if (!android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) return -EOPNOTSUPP;
    if (!blocked || !permission) return -EINVAL;
    const int error = ADnsHelper_setLegacyCallback(blocked);
    if (error) return error;
    sLegacyUidBlocked = blocked;
    sLegacyStatsPermission = permission;
    return 0;
}
static bool legacyNetworking() {
    return android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false);
}
static int legacyControl(const std::string& command) {
    int fd = TEMP_FAILURE_RETRY(open("/proc/net/xt_qtaguid/ctrl", O_WRONLY | O_CLOEXEC));
    if (fd < 0) return -errno;
    ssize_t count = TEMP_FAILURE_RETRY(write(fd, command.data(), command.size()));
    int err = count == static_cast<ssize_t>(command.size()) ? 0 : (count < 0 ? -errno : -EIO);
    close(fd);
    return err;
}''')
edit(C+'netd/NetdUpdatable.cpp','    android::netdutils::Status ret = sBpfHandler.init(cg2_path);',
'''    if (legacyNetworking()) {
        if (!sLegacyUidBlocked || !sLegacyStatsPermission) return -EOPNOTSUPP;
        // The kernel releases this process's tags when this retained FD closes.
        sLegacyProcessFd = TEMP_FAILURE_RETRY(open("/dev/xt_qtaguid", O_RDONLY | O_CLOEXEC));
        return sLegacyProcessFd >= 0 ? 0 : -errno;
    }
    android::netdutils::Status ret = sBpfHandler.init(cg2_path);''')
edit(C+'netd/NetdUpdatable.cpp','    return sBpfHandler.tagSocket(sockFd, tag, chargeUid, realUid);',
'''    if (legacyNetworking()) {
        if (!sLegacyStatsPermission) return -EOPNOTSUPP;
        if (chargeUid == 1029 || (chargeUid != realUid && !sLegacyStatsPermission(realUid))) return -EPERM;
        return legacyControl(android::base::StringPrintf("t %d %llu %u", sockFd,
            static_cast<unsigned long long>(tag) << 32, chargeUid));
    }
    return sBpfHandler.tagSocket(sockFd, tag, chargeUid, realUid);''')
edit(C+'netd/NetdUpdatable.cpp','    return sBpfHandler.untagSocket(sockFd);',
'''    if (legacyNetworking()) return legacyControl(android::base::StringPrintf("u %d", sockFd));
    return sBpfHandler.untagSocket(sockFd);''')
# DNS must use the same policy state as packet filtering rather than returning
# false when maps do not exist. Missing callbacks fail with an explicit error.
edit(C+'DnsResolver/DnsBpfHelper.cpp','#include <android-base/logging.h>',
'''#include <android-base/logging.h>
#include <android-base/properties.h>
#include "DnsHelperPublic.h"''')
edit(C+'DnsResolver/DnsBpfHelper.cpp','base::Result<void> DnsBpfHelper::init() {',
'''static bool (*sLegacyUidBlocked)(uid_t, bool) = nullptr;

base::Result<void> DnsBpfHelper::init() {
  if (android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
    if (!sLegacyUidBlocked)
      return base::Error(EOPNOTSUPP) << "Missing legacy firewall callback";
    return {};
  }''')
edit(C+'DnsResolver/DnsBpfHelper.cpp','  if (is_system_uid(uid)) return false;',
'''  if (android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
    if (!sLegacyUidBlocked) return base::Error(EOPNOTSUPP) << "Missing legacy firewall callback";
    return sLegacyUidBlocked(uid, metered);
  }
  if (is_system_uid(uid)) return false;''')
# Java API dispatch is handled by BpfNetMaps; JNI implementation is untouched
# for modern products and will never receive its mutation calls on this device.
B=C+'service/src/com/android/server/BpfNetMaps.java'
edit(B,'    private final INetd mNetd;',
     '    private final INetd mNetd;\n    private final Gta3xlwifiLegacyNetworkRules mLegacy;')
edit(B,'''        if (SdkLevel.isAtLeastT()) {
            ensureInitialized(context);
        }
        mNetd = netd;''', '''        mLegacy = Gta3xlwifiLegacyNetworkRules.enabled()
                ? new Gta3xlwifiLegacyNetworkRules(netd) : null;
        if (SdkLevel.isAtLeastT() && mLegacy == null) {
            ensureInitialized(context);
        }
        mNetd = netd;''')
methods={
'    public void addNaughtyApp(final int uid) {':'        if (mLegacy != null) { mLegacy.meteredUid(uid, false, true); return; }',
'    public void removeNaughtyApp(final int uid) {':'        if (mLegacy != null) { mLegacy.meteredUid(uid, false, false); return; }',
'    public void addNiceApp(final int uid) {':'        if (mLegacy != null) { mLegacy.meteredUid(uid, true, true); return; }',
'    public void removeNiceApp(final int uid) {':'        if (mLegacy != null) { mLegacy.meteredUid(uid, true, false); return; }',
'    public void setChildChain(final int childChain, final boolean enable) {':'        if (mLegacy != null) { mLegacy.setChildChain(childChain, enable); return; }',
'    public boolean isChainEnabled(final int childChain) {':'        if (mLegacy != null) return mLegacy.isChainEnabled(childChain);',
'    public void replaceUidChain(final int chain, final int[] uids) {':'        if (mLegacy != null) { mLegacy.replaceUidChain(chain, uids); return; }',
'    public void setUidRule(final int childChain, final int uid, final int firewallRule) {':'        if (mLegacy != null) { mLegacy.setUidRule(childChain, uid, firewallRule); return; }',
'    public int getUidRule(final int childChain, final int uid) {':'        if (mLegacy != null) return mLegacy.getUidRule(childChain, uid);',
'    private Set<Integer> getUidsMatchEnabled(final int childChain) throws ErrnoException {':'        if (mLegacy != null) return mLegacy.getUids(childChain);',
'    public void addUidInterfaceRules(final String ifName, final int[] uids) throws RemoteException {':'        if (mLegacy != null) { mLegacy.addInterfaceRules(ifName, uids); return; }',
'    public void removeUidInterfaceRules(final int[] uids) throws RemoteException {':'        if (mLegacy != null) { mLegacy.removeInterfaceRules(uids); return; }',
'    public void updateUidLockdownRule(final int uid, final boolean add) {':'        if (mLegacy != null) { mLegacy.updateLockdown(uid, add); return; }',
'    public void swapActiveStatsMap() {':'        if (mLegacy != null) return;  // qtaguid has a single kernel counter table.',
'    public void setNetPermForUids(final int permissions, final int[] uids) throws RemoteException {':'        if (mLegacy != null) { mLegacy.setNetPermForUids(permissions, uids); return; }',
'    public void setDataSaverEnabled(boolean enable) {':'        if (mLegacy != null) { mLegacy.setDataSaver(enable); return; }',
'    public void setIngressDiscardRule(final InetAddress address, final String iface) {':'        if (mLegacy != null) { mLegacy.setIngressDiscard(address, iface, true); return; }',
'    public void removeIngressDiscardRule(final InetAddress address) {':'        if (mLegacy != null) { mLegacy.setIngressDiscard(address, null, false); return; }',
'    public void setPullAtomCallback(final Context context) {':'        if (mLegacy != null) return;  // BPF map occupancy atom is not applicable.',
'    public void dump(final IndentingPrintWriter pw, final FileDescriptor fd, boolean verbose)\n            throws IOException, ServiceSpecificException {':'        if (mLegacy != null) { pw.println("SM-T510: iptables/qtaguid backend"); return; }',
}
for anchor,body in methods.items(): edit(B,anchor,anchor+'\n'+body)
# Destination-address ingress rejection (Android 14 VPN patch) needs explicit
# handling, not no-ops. It will be routed through the same netd backend below.
# A protected system-server IPC replaces the map-only NetworkStack query.
edit(B, '    private void maybeThrow(final int err, final String msg) {',
'''    public boolean isLegacyUidNetworkingBlocked(int uid, boolean metered) {
        if (mLegacy == null) throw new IllegalStateException("Not a legacy networking product");
        return mLegacy.isUidBlocked(uid, metered);
    }

    private void maybeThrow(final int err, final String msg) {''')
A=C+'framework/src/android/net/IConnectivityManager.aidl'
p=TOP/A;s=p.read_text();a=s.rfind('}')
if 'isLegacyUidNetworkingBlocked' not in s:
    p.write_text(s[:a]+'    boolean isLegacyUidNetworkingBlocked(int uid, boolean metered);\n'+s[a:])
S=C+'service/src/com/android/server/ConnectivityService.java'
edit(S, '    private boolean isUidCurrentlyDisallowedByPolicy(int uid) {',
'''    @Override
    public boolean isLegacyUidNetworkingBlocked(int uid, boolean metered) {
        enforceNetworkStackPermission(mContext);
        return mBpfNetMaps.isLegacyUidNetworkingBlocked(uid, metered);
    }

    private boolean isUidCurrentlyDisallowedByPolicy(int uid) {''')
M=C+'framework/src/android/net/ConnectivityManager.java'
edit(M,'        final BpfNetMapsReader reader = BpfNetMapsReader.getInstance();',
'''        // This device has a real iptables backend, so ask the policy owner.
        // Build.DEVICE is part of the stable SDK; no hidden property API is needed.
        if ("gta3xlwifi".equals(android.os.Build.DEVICE)) {
            try { return mService.isLegacyUidNetworkingBlocked(uid, isNetworkMetered); }
            catch (RemoteException e) { throw e.rethrowFromSystemServer(); }
        }
        final BpfNetMapsReader reader = BpfNetMapsReader.getInstance();''')

# The unversioned OEM extension is the supported place for device-only netd
# calls. Keep the frozen INetd ABI and restrict these controls to root/system.
O=N+'binder/com/android/internal/net/IOemNetd.aidl'
edit(O, '    void registerOemUnsolicitedEventListener(IOemNetdUnsolicitedEventListener listener);',
'''    void registerOemUnsolicitedEventListener(IOemNetdUnsolicitedEventListener listener);
    void gta3xlwifiStatsControl(int operation, int uid, int counterSet);
    void gta3xlwifiSetIngressDiscardRule(@utf8InCpp String address, @utf8InCpp String iface, boolean add);''')
edit(N+'OemNetdListener.h', '    ::android::binder::Status isAlive(bool* alive) override;',
'''    ::android::binder::Status isAlive(bool* alive) override;
    ::android::binder::Status gta3xlwifiStatsControl(int32_t operation, int32_t uid, int32_t counterSet) override;
    ::android::binder::Status gta3xlwifiSetIngressDiscardRule(const std::string& address, const std::string& iface, bool add) override;''')
edit(N+'OemNetdListener.cpp', '#include "OemNetdListener.h"',
'''#include "OemNetdListener.h"
#include "Gta3xlwifiLegacyFirewall.h"
#include "NetdConstants.h"
#include <binder/IPCThreadState.h>
#include <android-base/stringprintf.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>''')
edit(N+'OemNetdListener.cpp', '::android::binder::Status OemNetdListener::isAlive(bool* alive) {',
'''static ::android::binder::Status checkLegacyCaller() {
    const auto uid = ::android::IPCThreadState::self()->getCallingUid();
    if (uid != 0 && uid != 1000) return ::android::binder::Status::fromServiceSpecificError(EPERM);
    if (!::android::net::Gta3xlwifiLegacyFirewall::enabled())
        return ::android::binder::Status::fromServiceSpecificError(EOPNOTSUPP);
    return ::android::binder::Status::ok();
}
::android::binder::Status OemNetdListener::gta3xlwifiStatsControl(int32_t op, int32_t uid, int32_t set) {
    auto status = checkLegacyCaller(); if (!status.isOk()) return status;
    if (uid < 0 || (op != 1 && op != 2) || (op == 1 && set != 0 && set != 1))
        return ::android::binder::Status::fromServiceSpecificError(EINVAL);
    const std::string command = op == 1 ? ::android::base::StringPrintf("s %d %u", set, uid)
                                       : ::android::base::StringPrintf("d 0 %u", uid);
    std::lock_guard guard(::android::net::gBigNetdLock);
    int fd = TEMP_FAILURE_RETRY(open("/proc/net/xt_qtaguid/ctrl", O_WRONLY | O_CLOEXEC));
    if (fd < 0) return ::android::binder::Status::fromServiceSpecificError(errno);
    ssize_t count = TEMP_FAILURE_RETRY(write(fd, command.data(), command.size()));
    int error = count == static_cast<ssize_t>(command.size()) ? 0 : (count < 0 ? errno : EIO);
    close(fd);
    return error ? ::android::binder::Status::fromServiceSpecificError(error) : ::android::binder::Status::ok();
}
::android::binder::Status OemNetdListener::gta3xlwifiSetIngressDiscardRule(
        const std::string& address, const std::string& iface, bool add) {
    auto status = checkLegacyCaller(); if (!status.isOk()) return status;
    std::lock_guard guard(::android::net::gBigNetdLock);
    int result = ::android::net::Gta3xlwifiLegacyFirewall::get().setIngressDiscard(address, iface, add);
    return result ? ::android::binder::Status::fromServiceSpecificError(-result) : ::android::binder::Status::ok();
}

::android::binder::Status OemNetdListener::isAlive(bool* alive) {''')
edit(C+'service/Android.bp','        "netd-client",',
     '        "netd-client",\n        "oemnetd_aidl_interface-java",')
# Permit inclusion in the source-built service APEX; the OEM interface remains
# hidden and is never part of an SDK surface.
edit(N+'Android.bp', '    name: "oemnetd_aidl_interface",',
'''    name: "oemnetd_aidl_interface",
    backend: {
        java: {
            sdk_version: "system_server_current",
            min_sdk_version: "30",
            apex_available: ["com.android.tethering"],
        },
    },''')
edit(C+'DnsResolver/Android.bp', '    name: "libcom.android.tethering.dns_helper",',
     '    name: "libcom.android.tethering.dns_helper",\n    whole_static_libs: [],')
# libdl is needed for the private in-process resolver callback.
p=TOP/(C+'DnsResolver/Android.bp');s=p.read_text()
start=s.index('    name: "libcom.android.tethering.dns_helper",')
end=s.index('\n}', start)
a=s[start:end]
if '"libdl"' not in a:
    a=a.replace('        "libbase",','        "libbase",\n        "libdl",',1)
    p.write_text(s[:start]+a+s[end:])
p=TOP/(C+'netd/Android.bp');s=p.read_text()
# libnetd_updatable already links libdl on upstream; if necessary add it only
# to the shared library module, not to its unrelated tests.
start=s.index('    name: "libnetd_updatable",');end=s.index('\n}',start);a=s[start:end]
if '"libdl"' not in a:
    a=a.replace('        "libbase",','        "libbase",\n        "libdl",',1)
    p.write_text(s[:start]+a+s[end:])
# Stats are actual cumulative qtaguid data, not empty BPF records.
ST=C+'service-t/native/libs/libnetworkstats/'
for p in (PORT/'compat/networkstats').iterdir(): shutil.copy2(p,TOP/ST/p.name)
edit(ST+'Android.bp','        "BpfNetworkStats.cpp",',
     '        "BpfNetworkStats.cpp",\n        "Gta3xlwifiLegacyStats.cpp",')
edit(ST+'BpfNetworkStats.cpp','#include "netdbpf/BpfNetworkStats.h"',
     '#include "netdbpf/BpfNetworkStats.h"\n#include "Gta3xlwifiLegacyStats.h"')
stat_methods={
'void bpfRegisterIface(const char* iface) {':'    if (gta3xlwifiLegacyStatsEnabled()) return;  // kernel qtaguid tracks interfaces.',
'int bpfGetUidStats(uid_t uid, StatsValue* stats) {':'    if (gta3xlwifiLegacyStatsEnabled()) return gta3xlwifiLegacyUidStats(uid, stats);',
'int bpfGetIfaceStats(const char* iface, StatsValue* stats) {':'    if (gta3xlwifiLegacyStatsEnabled()) return gta3xlwifiLegacyIfaceStats(iface, stats);',
'int bpfGetIfIndexStats(int ifindex, StatsValue* stats) {':'''    if (gta3xlwifiLegacyStatsEnabled()) {
        char iface[IF_NAMESIZE];
        if (!if_indextoname(ifindex, iface)) return -errno;
        return gta3xlwifiLegacyIfaceStats(iface, stats);
    }''',
'int parseBpfNetworkStatsDetail(std::vector<stats_line>* lines) {':'    if (gta3xlwifiLegacyStatsEnabled()) return gta3xlwifiLegacyDetail(lines);',
'int parseBpfNetworkStatsDev(std::vector<stats_line>* lines) {':'    if (gta3xlwifiLegacyStatsEnabled()) return gta3xlwifiLegacyDev(lines);',
}
for anchor,body in stat_methods.items(): edit(ST+'BpfNetworkStats.cpp',anchor,anchor+'\n'+body)
# Stats factory creates a BpfNetMaps wrapper too. Give the legacy wrapper the
# same netd binder instead of the map-only constructor's null placeholder.
edit(B, '        this(context, null);',
'''        this(context, Gta3xlwifiLegacyNetworkRules.enabled()
                ? INetd.Stub.asInterface((android.os.IBinder) context.getSystemService(Context.NETD_SERVICE)) : null);''')
F=C+'service-t/src/com/android/server/net/NetworkStatsFactory.java'
edit(F,'            mPersistSnapshot.combineAllValues(stats);',
'''            if (android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)) {
                // qtaguid records are cumulative; adding them on each poll overcounts.
                mPersistSnapshot = stats;
            } else {
                mPersistSnapshot.combineAllValues(stats);
            }''')
NS=C+'service-t/src/com/android/server/net/NetworkStatsService.java'
edit(NS,'    protected INetd mNetd;',
'''    protected INetd mNetd;
    private final com.android.internal.net.IOemNetd mLegacyOem;''')
edit(NS,'        mNetd = Objects.requireNonNull(netd, "missing Netd");',
'''        mNetd = Objects.requireNonNull(netd, "missing Netd");
        try {
            mLegacyOem = android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)
                    ? com.android.internal.net.IOemNetd.Stub.asInterface(netd.getOemNetd()) : null;
        } catch (RemoteException e) { throw new IllegalStateException("Missing legacy stats backend", e); }''')
# Do not attempt to open non-existent maps; the parser and OEM stats RPCs replace
# all operations on them, while optional BPF occupancy/tracing is unsupported.
for signature in [
'public IBpfMap<S32, U8> getUidCounterSetMap()',
'public IBpfMap<CookieTagMapKey, CookieTagMapValue> getCookieTagMap()',
'public IBpfMap<StatsMapKey, StatsMapValue> getStatsMapA()',
'public IBpfMap<StatsMapKey, StatsMapValue> getStatsMapB()',
'public IBpfMap<UidStatsMapKey, StatsMapValue> getAppUidStatsMap()',
'public IBpfMap<S32, StatsMapValue> getIfaceStatsMap()',
]:
    anchor='        '+signature+' {'
    edit(NS,anchor,anchor+'\n            if (android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)) return null;')
edit(NS,'        mHandler.post(mSkDestroyListener::start);',
'''        if (!android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false))
            mHandler.post(mSkDestroyListener::start);  // qtaguid cleans socket tags in kernel.''')
edit(NS,'        public boolean supportEventLogger(Context ctx) {',
'''        public boolean supportEventLogger(Context ctx) {
            if (android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)) return false;''')
edit(NS,'    private void setKernelCounterSet(int uid, int set) {',
'''    private void setKernelCounterSet(int uid, int set) {
        if (mLegacyOem != null) {
            try { mLegacyOem.gta3xlwifiStatsControl(1, uid, set); }
            catch (RemoteException | ServiceSpecificException e) { Log.e(TAG, "qtaguid counter set update failed", e); }
            return;
        }''')
edit(NS,'    private void deleteKernelTagData(int uid) {',
'''    private void deleteKernelTagData(int uid) {
        if (mLegacyOem != null) {
            try { mLegacyOem.gta3xlwifiStatsControl(2, uid, 0); }
            catch (RemoteException | ServiceSpecificException e) { Log.e(TAG, "qtaguid UID cleanup failed", e); }
            return;
        }''')
edit(NS, '    private void dumpIfaceStatsMapLocked(final IndentingPrintWriter pw) {',
'''    private void dumpIfaceStatsMapLocked(final IndentingPrintWriter pw) {
        if (mLegacyOem != null) { pw.println("Interface counters: kernel qtaguid"); return; }''')
H=C+'service-t/src/com/android/server/net/BpfInterfaceMapHelper.java'
edit(H,'        public IBpfMap<S32, InterfaceMapValue> getInterfaceMap() {',
'''        public IBpfMap<S32, InterfaceMapValue> getInterfaceMap() {
            if (android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)) return null;''')
edit(H, '    public String getIfNameByIndex(final int index) {',
'''    public String getIfNameByIndex(final int index) {
        if (android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)) {
            try {
                java.net.NetworkInterface iface = java.net.NetworkInterface.getByIndex(index);
                return iface == null ? null : iface.getName();
            } catch (java.net.SocketException e) { Log.e(TAG, "Interface lookup failed", e); return null; }
        }''')

# CLAT translation runs in userspace on this kernel. Keep checking executable
# permissions, but require BPF pins only on products that actually load BPF.
J=C+'service/jni/com_android_server_connectivity_ClatCoordinator.cpp'
edit(J, '#include <bpf/BpfMap.h>', '#include <bpf/BpfMap.h>\n#include <android-base/properties.h>')
edit(J, '    // Move on to verifying that the bpf programs and maps are as expected.',
     '    if (android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {\n'
     '        if (fatal) abort();\n        return;\n    }\n\n'
     '    // Move on to verifying that the bpf programs and maps are as expected.')
CL=C+'service/src/com/android/server/connectivity/ClatCoordinator.java'
for signature in ['public IBpfMap<ClatIngress6Key, ClatIngress6Value> getBpfIngress6Map()',
                  'public IBpfMap<ClatEgress4Key, ClatEgress4Value> getBpfEgress4Map()',
                  'public IBpfMap<CookieTagMapKey, CookieTagMapValue> getBpfCookieTagMap()']:
    anchor='        '+signature+' {'
    edit(CL,anchor,anchor+'\n            if (android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)) return null;')
edit(CL, '    private void untagSocket(long cookie) throws IOException {',
"""    private void untagSocket(long cookie) throws IOException {
        if (android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)) {
            if (mLegacyClatSocket == null) return;
            final ParcelFileDescriptor socket = mLegacyClatSocket;
            mLegacyClatSocket = null;
            try { native_tagLegacyClatSocket(socket.getFileDescriptor(), false); }
            finally { socket.close(); }
            return;
        }""")
edit(CL, """            cookie = mDeps.getSocketCookie(writeSock6.getFileDescriptor());
            tagSocketAsClat(cookie);""", """            if (android.os.SystemProperties.getBoolean("ro.gta3xlwifi.legacy_networking", false)) {
                mLegacyClatSocket = ParcelFileDescriptor.dup(writeSock6.getFileDescriptor());
                try { native_tagLegacyClatSocket(writeSock6.getFileDescriptor(), true); }
                catch (IOException e) {
                    mLegacyClatSocket.close(); mLegacyClatSocket = null;
                    throw e;
                }
                cookie = 0;
            } else {
                cookie = mDeps.getSocketCookie(writeSock6.getFileDescriptor());
                tagSocketAsClat(cookie);
            }""")
# The socket stays in system_server until inherited by clatd. Tag the actual
# socket with CLAT UID, retaining its qtaguid accounting exclusion.
edit(CL, '    private static native long native_getSocketCookie(FileDescriptor sock)',
     '    private static native void native_tagLegacyClatSocket(FileDescriptor sock, boolean tag) throws IOException;\n\n'
     '    private static native long native_getSocketCookie(FileDescriptor sock)')
edit(J, 'static const JNINativeMethod gMethods[] = {', """static void tagLegacyClatSocket(JNIEnv* env, jclass, jobject sock, jboolean tag) {
    if (!android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
        throwIOException(env, "Not a legacy networking device", EOPNOTSUPP);
        return;
    }
    static const int processFd = TEMP_FAILURE_RETRY(open("/dev/xt_qtaguid", O_RDONLY | O_CLOEXEC));
    if (processFd < 0) { throwIOException(env, "qtaguid process tracking unavailable", ENODEV); return; }
    const int socketFd = netjniutils::GetNativeFileDescriptor(env, sock);
    if (socketFd < 0) { throwIOException(env, "Invalid CLAT socket", EBADF); return; }
    const std::string command = tag ? "t " + std::to_string(socketFd) + " 0 1029"
                                    : "u " + std::to_string(socketFd);
    const int fd = TEMP_FAILURE_RETRY(open("/proc/net/xt_qtaguid/ctrl", O_WRONLY | O_CLOEXEC));
    if (fd < 0) { throwIOException(env, "qtaguid open failed", errno); return; }
    const ssize_t written = TEMP_FAILURE_RETRY(write(fd, command.data(), command.size()));
    const int error = written == static_cast<ssize_t>(command.size()) ? 0 : (written < 0 ? errno : EIO);
    close(fd);
    if (error) throwIOException(env, "qtaguid CLAT socket tagging failed", error);
}

static const JNINativeMethod gMethods[] = {
    { "native_tagLegacyClatSocket", "(Ljava/io/FileDescriptor;Z)V", (void*) tagLegacyClatSocket },""")

# The global (chain zero) firewall still belongs to FirewallController. Android
# 14 removed its UID operation together with the BPF-only child-chain API.
edit(N+'FirewallController.h', '  std::set<std::string> mIfaceRules;',
     '  std::set<std::string> mIfaceRules;\n  std::set<int> mLegacyUidRules;')
edit(N+'FirewallController.cpp', '    mIfaceRules.clear();',
     '    mIfaceRules.clear();\n    mLegacyUidRules.clear();')
edit(N+'FirewallController.cpp', 'int FirewallController::isFirewallEnabled(void) {', """int FirewallController::setUidRule(ChildChain chain, int uid, FirewallRule rule) {
    if (!Gta3xlwifiLegacyFirewall::enabled() || chain != NONE || uid < 0 ||
        (rule != static_cast<FirewallRule>(0) && rule != ALLOW && rule != DENY)) return -EINVAL;
    const bool list = mFirewallType == ALLOWLIST;
    const bool add = list ? rule == ALLOW : rule == DENY;
    const bool exists = mLegacyUidRules.count(uid);
    if (exists == add) return 0;
    std::string command = "*filter\\n";
    for (const char* parent : {LOCAL_INPUT, LOCAL_OUTPUT})
        StringAppendF(&command, "%s %s -m owner --uid-owner %d -j %s\\n",
                      add ? "-I" : "-D", parent, uid, list ? "RETURN" : "DROP");
    command += "COMMIT\\n";
    const int res = execIptablesRestore(V4V6, command);
    if (res) return -EREMOTEIO;
    if (add) mLegacyUidRules.insert(uid); else mLegacyUidRules.erase(uid);
    return 0;
}

int FirewallController::isFirewallEnabled(void) {""")
edit(N+'FirewallController.cpp', '#include "FirewallController.h"',
     '#include "FirewallController.h"\n#include "Gta3xlwifiLegacyFirewall.h"')

# Pass callbacks explicitly across the APEX library boundary. RTLD_DEFAULT may
# not see netd's executable from an isolated linker namespace.
edit(C+'netd/libnetd_updatable.map.txt', '    libnetd_updatable_init; # apex',
     '    libnetd_updatable_init; # apex\n    libnetd_updatable_setLegacyCallbacks; # apex')
edit(C+'netd/Android.bp', '        "libnetdutils",\n    ],\n    export_include_dirs:', '        "libnetdutils",\n        "libcom.android.tethering.dns_helper",\n    ],\n    export_include_dirs:')
edit(C+'DnsResolver/libcom.android.tethering.dns_helper.map.txt', '    ADnsHelper_init; # apex',
     '    ADnsHelper_init; # apex\n    ADnsHelper_setLegacyCallback; # apex')
edit(C+'DnsResolver/DnsBpfHelper.cpp', '}  // namespace android', """}  // namespace android

extern "C" int ADnsHelper_setLegacyCallback(bool (*blocked)(uid_t, bool)) {
    if (!android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) return -EOPNOTSUPP;
    if (!blocked) return -EINVAL;
    android::net::sLegacyUidBlocked = blocked;
    return 0;
}""")
edit(N+'main.cpp', '    if (libnetd_updatable_init(cg2_path.c_str())) {', """    if (::android::net::Gta3xlwifiLegacyFirewall::enabled() &&
        libnetd_updatable_setLegacyCallbacks(&gta3xlwifi_legacy_is_uid_networking_blocked,
                                            &gta3xlwifi_legacy_has_stats_permission)) {
        ALOGE("Legacy firewall callback registration failed");
        exit(1);
    }
    if (libnetd_updatable_init(cg2_path.c_str())) {""")
# A policy read error must block the legacy DNS request, not become `== 1`
# false. Preserve normal upstream behavior for every non-legacy product.
D='packages/modules/DnsResolver/DnsProxyListener.cpp'
edit(D, '#include <android-base/parseint.h>', '#include <android-base/parseint.h>\n#include <android-base/properties.h>')
edit(D, '    if (!ADnsHelper_isUidNetworkingBlocked) return false;', """    if (android::base::GetBoolProperty("ro.gta3xlwifi.legacy_networking", false)) {
        if (!ADnsHelper_isUidNetworkingBlocked) return true;
        const int result = (*ADnsHelper_isUidNetworkingBlocked)(uid, resolv_is_metered_network(netId));
        return result != 0;
    }
    if (!ADnsHelper_isUidNetworkingBlocked) return false;""")

# Binder descriptors are wire protocol names. JarJar must not rewrite the OEM
# interface name or its generated descriptor strings.
edit(C+'service/jarjar-excludes.txt',
     "# Classes loaded by SystemServer via their hardcoded name, so they can't be jarjared",
     '# OEM binder wire descriptors must stay compatible with native netd.\n'
     r'com\.android\.internal\.net\.IOemNetd(\$.+|UnsolicitedEventListener(\$.+)?)?'+'\n'
     "# Classes loaded by SystemServer via their hardcoded name, so they can't be jarjared")
print('Legacy filtering, explicit DNS/socket callbacks, VPN ingress and real counter accounting port prepared.')

edit(CL, '    private ClatdTracker mClatdTracker = null;',
     '    private ClatdTracker mClatdTracker = null;\n    private ParcelFileDescriptor mLegacyClatSocket;')
