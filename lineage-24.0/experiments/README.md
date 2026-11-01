# Inherited work in progress

The new [Android 17 combined candidate](port-20261101/) adapts the final
networking/kernel graph to the new sources and direct DNS API. It remains isolated.

The October-dated directories are exact copies of the isolated LineageOS 23.2 research,
including source locks, patches, tests, failures and evidence limitations. They
are carried forward for the LineageOS 24 port; their Android 16 test results are
not Android 17 validation. None is applied by `tools/validate-port.sh`.

Do not run their archived builders: they refer to deleted 23.2 paths and used
fresh-output names. Prepare new 24 runners and regenerate all source-bound
Android 17 policy/network oracles first.

Kernel candidate graph against the original kernel input:

1. qtaguid-persistent-20261022-02
2. kernel-policy-reader-20261023-01
3. kernel-functionfs-20261023-01 (already includes NNP02)

Do not stack NNP-only with the combined FunctionFS patch. The kernel Git baseline
is unchanged on `lineage-24.0`; current Android prebuilts remain the original
Image/DTBO/vendor. Extended socket classes, unsupported netlink policycaps and
whole-policy enforcement still need investigation against actual Android 17.

Networking remains incomplete: real netd ownership, packet enforcement,
permissions, quotas, restart recovery, Java/module integration and runtime tests
must be completed against the new Connectivity/DnsResolver sources. No BPF
readiness or successful enforcement is fabricated.
