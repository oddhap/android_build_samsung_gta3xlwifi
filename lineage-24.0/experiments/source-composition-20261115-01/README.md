# Selected source composition and actual Soong integration

Snapshot port-20261115-01 selects109 files, with1243 projects/20 exact project
patches audited before/after, over the preserved17-patch parent. Every unchanged
candidate source is matched against its prior successful report and actual source
hash. Individual original files are backed up on the server; no device/kernel/
prebuilt/policy/signing/user-data file is part of this selection.

The composition includes the complete CLAT/native16/Java/loopback/stats candidate,
permission service Kotlin sources and default-method API/current.txt, ten actual
iptables extension sources/headers, DNS callback/source/exports, updatable netd
callbacks/exports and private loader init selection. DNS helper sources belong to
Connectivity/bpf/dns_helper; the resolver source/export belongs to DnsResolver.

The Soong changes explicitly declare18 native implementation units and their
shared dependencies; add IGta3xlwifiNetpolicy to the existing unstable OEM CPP
interface; add a separate system_server_current/min31/Tethering Java AIDL library;
connect that static dependency to service-connectivity; and preserve original
Binder descriptors with the narrowly scoped jarjar exclusions already validated.
INetd and existing protocol ordinals are preserved. Existing iptables globs build
the ten extensions using the actual registry generator.

network-composition-build-20261115-01 runs actual m -j12 netd iptables
libnetd_resolv libnetd_updatable service-connectivity services.permission. Soong
Android.bp graph analysis/generation has passed. Make/Kati and actual module
compilation now complete exit0, including R8, native header ABI checks, permission
Kotlin and current server API checking. All1243/20 after-audits pass. Installed
post-R8 DEX/native outputs are separately verified in network-composition-outputs02. No flash-ready ROM exists.

The selected kernel and policy are intentionally unchanged pending their explicit
reviewed source/input selection and full product validation. Historical isolated
proofs remain historical: the normal build may now replace their referenced old
TOP/intermediate hashes. Their reports must not be modified to conceal that.
