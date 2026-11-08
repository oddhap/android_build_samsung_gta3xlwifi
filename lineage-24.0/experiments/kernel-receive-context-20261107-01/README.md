# Socket-aware receive LNA stage

This isolated proposal supplies the actual full receiving socket to the LNA
predicate at `sk_filter_trim_cap`, after the existing pfmemalloc check and before
the unchanged LSM and socket-filter path. Early netfilter INPUT can have no socket
and incorrectly normalize overflow UID to root; it is not the attachment used here.
The original function is byte-identical after removing the inserted policy call.
No skb socket, owner, data or reference is changed. The original caller protects
socket lifetime. Mutable socket UID is used; immutable creator UID is reserved
for the separate loopback receiver identity requirement.

The real qtaguid tag-tree lock protects a copied accounting UID/tag snapshot.
Only accounting UID1051 plus tag0xffffff82 exempts system DNS from LNA; process UID
alone does not. Passive accounting errors fail closed. The entire policy decision
holds the actual RCU reader domain drained by the selected kernel's
`synchronize_net()`, including the shared held gate and DNS lookup. Initial/held
gate denial precedes the exemptions. Capability bit32 describes this compiled
primitive, not complete networking readiness.

The exact signed L3-relative read handles receive packets whose network header
precedes skb data. Actual Android17 parser comparisons cover 5,632 combinations
of family, all protocol numbers and positive/negative headroom. The final host
run and full build each pass51 assertions, including contended HOLD draining,
mutable UID/permissions, wrong/absent skb owner, locked tag snapshots and preserved
LSM/socket-filter errors. Host RCU/socket/tag/copy fixtures are not device execution.
The earlier40/42-case run is historical; the51-case report binds the current tool.

Full kernel/modules: `kernel-receive-context-build-20261107-01` exit0;
Image SHA256 `808468364a79c037930089f4d5f2d63085ca7fdc52b9d0646a47c5ff59381529`.
Configuration remains `fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea`.
All60,349 candidate/60,331 protected tracked hashes and Android1,243 projects/17
patches agree before/after. Gator118 and KUTF43 imported versions match.
The actual ARM64 xtables archive/link retains70 original+7 private registrations,
with all77 registrations and source audits passing. Pipeline exit0.
Collected evidence contains source/log/hash metadata only; binaries stay remote.

No Android prebuilt is promoted. This is LNA/shared gate receive coverage, not
ordinary UID firewall/VPN/IIF/accounting or loopback metrics completeness. Native
LNA transport, atomic combined publication, startup and runtime validation remain.
The authoritative reference attachment is Linuxv6.6 `net/core/filter.c` and
`kernel/bpf/cgroup.c`; reference provenance is recorded in
`receive-socket-context-20261107-01`. UDP encapsulation hooks precede ordinary
socket filtering in both selected4.4 and modern6.6; this is not blanket coverage
of every encapsulated packet. No first test ROM may claim networking readiness
from these component tests.
