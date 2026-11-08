# Leased two-table LNA image transport

Private NetpolicyLease readLocalNetwork/replaceLocalNetwork implement the real
kernel6757/6758 two-table protocol. The store primitive feature bit is required,
without claiming packet attachment or complete networking readiness. Metadata is
bounded, reserved fields/pointers/version/revision/counts checked, both table data
arrays validated as strict canonical sorted unique prefixes. Both networks and
host allowlist share one revision/image. Inputs must already be canonical; the
separate LocalNetworkState owns BPF-equivalent suffix normalization.

Replacement requires actual held state and expected generation, allocates all
wire/readback arrays before SET, then verifies exact coherent readback of both
tables and the still-held state. Only then changes caller revision. It never
releases or publishes. Protocol/kernel uncertainty closes the real lease, rearming
the gate. EINTR after commit is safely replayed against the kernel idempotence
contract. Local invalid input leaves an existing lease and output untouched.

local-network-transport-host-20261108-01 passes696 checks plus original90 UID
transport regressions. All193 prefix lengths/ignored next bit,1000 entries in EACH
table, empty network/host/both,16 concurrent readers, stale revisions, malformed
metadata/data, both independent value readback mismatches and ambiguous writes
are covered with syscall/device fixtures and fatal UBSan. No real kernel packets.

local-network-transport-native-20261108-01 passes actual Android17 netd ARM64 CFI
compilation and ARM32/ARM64 ABI compilation/link: transfer40B,entry32B,revision16,
network pointer24,host pointer32, SET40286757/GETc0286758. All1243 projects/17 exact
patches match before/after. The prior UID24/8 ABI checks remain. Protected TOP
objects and actual kernel UAPI are hash bound and unchanged. No full netd link,
source promotion, callback publication or hardware execution.
