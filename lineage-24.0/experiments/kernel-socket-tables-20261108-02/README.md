# Dedicated socket-stage tables

Private per-netns g24sock IPv4/IPv6 tables register default INPUT/OUTPUT DROP with
NO global netfilter hooks. Their explicit evaluator binds/restores the actual
supplied full socket and L3 cursor, passes the actual current device/netns and
preserves caller ownership. Invalid metadata fails closed before mutation.
Read-only matches and standard ACCEPT/DROP/RETURN/validated jumps plus terminal
ERROR are the only permitted translated rules. Packet-consuming/modifying targets
such as REJECT/NFQUEUE are rejected by the common native/compat replacement path.
Other table replacement bodies are byte-identical after removing the private
inserts. Root/init-CAP_NET_ADMIN rule helpers can replace the private table only
while an exclusive real lease exists and is held; mutex spans replacement. Rule
helper children are intentionally not the parent lease's TGID, and receive no FD.

Late init avoids dependence on net/ link order: both ip_tables families must have
registered standard/ERROR targets first. Registration failure leaves the evaluator
closed without accessing a freed net_generic slot. Allocation/registration unwind,
separate namespaces, safe grammar, live socket UID binding, cursor/length/ownership
restoration and exact core insertion points pass52 host cases/864 comparisons.
Kernel tables/evaluation/credentials/RCU/netns effects in those tests are fixtures,
not real iptables syscall or packet execution.

kernel-socket-tables-build-20261108-02 passes full Image/modules, all regressions
(including1797 loopback/98304 permission comparisons), configfac42 unchanged,
60354 candidate/60331 protected tracked hashes and1243 projects/17 exact Android
patches matching before/after. Gator118/KUTF43 imports match.
Image dbac36624b2de3cf89122668507041d7132ef77a80b86f64c11dfdbea9d5bf44.
Pipeline exit0, including actual Android17 CFI compilation of the checked I/O.
Attempt01's missing declaration is preserved separately. No prebuilt promotion.

This registers a safe primitive, not complete owner semantics or an attachment.
Root bootstrap, atomic multi-table ownership, UID snapshot consistency across
individual matches, VPN/IIF/accounting, authoritative Binder/Java/startup and real
metrics delivery remain mandatory. Do not blindly attach the old early roots or
repeat foreign filter tables. No global networking-ready or BPF flag is changed.
