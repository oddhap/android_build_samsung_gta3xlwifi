# Native platform compatibility fixes

These patches restore the existing Android iptables/xt_qtaguid path for kernels
without the Android 12 eBPF backports. They do not turn off SELinux or substitute
an unconditional success result for firewall operations. The property
`ro.kernel.ebpf.supported=false` selects the restored legacy implementation.

Changes were cherry-picked without conflicts into isolated copies of the exact
LineageOS projects from the saved manifest, then exported as aggregate diffs.
The original fork is not substituted for the current LineageOS source tree.
Compilation and hardware testing are separate requirements.

Primary sources:

- https://github.com/rINanDO/android_system_bpf/tree/lineage-19.1
- https://github.com/rINanDO/android_system_netd/tree/lineage-19.1

BPF commits: `bddf9644333d328d398200be7cce571c943a4db4`,
`6405acaaf6c7836c0d4c12f524547d262f1cfd12`.

Netd commits, in application order:

1. `e7ef83617f5c346fac37a2d9d1855777f811fc9a`
2. `6aef1a02f7dbed98cb835ebaa4109f21237ddd55`
3. `6a0f369dc3395567bc3892d8c5396781b28dfaee`
4. `efab72b5139ec148a924418e6f5737b5ffb6b01e`
5. `0bc11b383a2a6d59e04fcabd3b8bfd19e3993272`
6. `ae2c92154149f6bd317f3dbb8e31ed534d4f3859`
7. `926dd1c221b51e6d095fb657e84d4af54805a8e5`
8. `adaf6ad452d35b939c4b81389c8740c130c02a52`

The source-built kernel has `CONFIG_NETFILTER_XT_MATCH_QTAGUID=y`; that driver
also registers the iptables `owner` match. NetworkStatsFactory and platform
SELinux rules retain the qtaguid interfaces. Runtime tests must still cover
traffic accounting, app firewall rules, Wi-Fi and tethering.

`device-kernel-profile.patch` adds a Soong switch for this product's kernel
requirements. The device selects its own P/4.4 profile; other products select
the original upstream profile. Five networking constraints reflect the restored
implementation: QTAGUID is required, while BPF_SYSCALL, CGROUP_BPF, NET_CLS_BPF
and the separate OWNER driver are absent. QTAGUID itself implements the owner
match. Tethering's BPF offload resource is disabled in the device overlay.

This adaptation is not a claim of compliance with unmodified Android kernel
requirements. The original check failure is saved in the project notes. HAL,
kernel, SELinux and physical hardware behavior still require validation.

`systemui-tuner-lifecycle.patch` pairs the status-bar fragment's `addTunable`
registration with `removeTunable` in `onDestroyView`. A real first-setup crash
showed a detached fragment receiving an icon blacklist update with a null
context. This fixes the listener lifetime rather than hiding the exception.
The patch targets frameworks/base 5f6b8d6098f8d858d1450db45c350c7ba08ae455;
`tools/apply-systemui-fix.py` checks that revision and applies it idempotently.
