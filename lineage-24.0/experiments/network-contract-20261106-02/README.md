# Actual networking source contracts

Read-only source/generated-code evidence, with complete Android source audits.
The selected CP2A local-network and loopback permission flags are ENABLED and
READ_ONLY. Actual generated framework Flags.java getters return true. These
security features cannot be dismissed as disabled/optional on this selected build.

The frozen kernel config enables ANDROID_PARANOID_NETWORK. Actual IPv4 and IPv6
socket-create paths reject callers without group3003 or CAP_NET_RAW. Android17's
platform.xml still assigns the inet group for INTERNET. This is existing source/
build evidence, not a new permission bypass or a device execution test.

Current Java BpfNetMaps still opens actual BPF maps on T+, and native updatable
initialization aborts on real BpfHandler failure. Netd's stable public AIDL version
is18. A complete real legacy provider/startup/query implementation remains needed;
neither maps nor readiness may be fabricated. No flag or policy input is changed.
Attempt01 failed only because the audit expected a numeric AID_INET definition;
the kernel uses typed KGIDT_INIT(3003). Exact typed validation fixes the tool, and
attempt02 passes. Both failed/successful complete source audits are preserved.
