# Serialized committed UID policy transactions

Combines the nine ordinary programs and three metered programs with aggregate
rule/byte validation. One mutex serializes lifecycle, copy/mutate/compile/commit
and query publication. Start leaves the real leased barrier held, with no query
value. Explicit full initial replacement is required. Mutators require a prior
committed state. Publication follows actual DualStackUidChains verification of
both families and release acknowledgement. Every I/O error withdraws the value,
closes the lease and requires explicit restart/full replacement. Pure validation
failures perform no I/O and preserve the prior committed value. Missing-state
queries return EAGAIN and preserve output. No callback or readiness is registered.

The ordinary membership selector is explicitly RawUid. Actual Android17
bpf_traffic_account reads bpf_get_socket_uid before bpf_owner_match; it does NOT
perform the optional qtaguid receive-side socket lookup. The raw appId core view
must precede ordinary dispatch and normalize literal65534. LookupAppId is a
separate available primitive, not a substitute for this packet identity.
The previous ordinary proposal's default Owner selector is superseded here.
The value-level Java/DNS UID query still follows its own A17 query contract.

Host03 passes152 cases with all seven actual C++ components and syscall/table
fixtures: combined size failure after each part separately fits, explicit initial
state, no publication before commit, user/admin/Data Saver, invalid input without
I/O, both-family partial writes/failed acknowledgements with/without commit,
rollback quarantine, lease failure after possible release, restart,24 concurrent
mutations and readers admitted during paused IPv6 success/failure. The first
fixture failed a misleading-indentation warning and is retained. Host02 passes
on the earlier Owner-selector staging;03 binds the final raw selector.
Raw ordinary fixture01 passes38 cases plus1048576 actual A17 predicate comparisons,
checks every nontrivial selector is RawUid, and exercises nondefault overflowuid
versus a distinct slow-lookup UID. No packet execution is claimed.

Native01 compiled all seven CFI sources before the raw-selector correction;
Native02 checks the final staging with complete Android source audits. This is
an inactive UID subsystem, not a complete netd backend, dispatcher or executable
network service. Mandatory LNA/loopback/VPN/interface/CLAT/tagging, startup,
Java/DNS/private provider and real attachment ownership remain incomplete. A
released UID gate must not be used as whole-network readiness or activation.
