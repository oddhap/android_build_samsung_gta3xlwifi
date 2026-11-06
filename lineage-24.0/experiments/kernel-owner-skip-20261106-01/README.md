# Ordinary owner-rule packet exemption

A separate private revision0 four-byte zero-reserved match, enabled by the
existing builtin QTAGUID config. Only IPv4/IPv6 INPUT/OUTPUT and the initial user
namespace are accepted. It matches ESP, TCP RST and ingress TCP FIN, mirroring
actual A17 parse_skb/skip_owner_match semantics. It never implements a UID/core,
blanket loopback, Data Saver, local-network or VPN exemption.

The parser reads relative to skb's actual network header, with full zeroing on
failed reads. IPv4 IHL must be45..4f. IPv6 skips exactly one hop/destination option
header, including A17's uint8 offset wrapping. Other extensions are not silently
parsed more deeply. Failed reads retain exactly the reference's zero semantics.
No packet header/payload, accounting, owner rev1 or existing match is changed.

Host fixture02 passes11 cases plus5774610 comparisons against extracted ACTUAL
Android17 parse_skb and skip_owner_match functions and their packet/offset types.
Cases include all IPv4 first bytes/protocols, all IPv6 next protocols and option
lengths, TCP flags/directions, L2-offset fixtures, truncated headers and byte-load
failures. Fixtures model modern relative L3 helper semantics; they do not claim
that this old kernel executes modern BPF. Fixture01 failed a missing test-only
annotation macro, corrected without changing the candidate. Logs are retained.

The isolated full kernel/modules runner preserves all prerequisites and checks
full tracked/protected/Android source audits, original config and Gator/KUTF CRCs.
The userspace prerequisite is xtables-owner-skip-20261106-01. Neither proposal is
selected in Android prebuilts. Parent dispatch still needs separate raw appId
core handling, per-interface BACKGROUND behavior and all other mandatory policy.

Full `kernel-owner-skip-build-20261106-01` exits0. Image SHA256:
`b3b10669196c8864c6d6be0759b545db8e109f4f7e10ce0fb9604decc9665986`.
Original config fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea
is preserved; Gator118 and KUTF43 module CRC checks pass. Complete60338 candidate,
60331 protected tracked-source audits and Android1243/17 audits pass before/after.
All prior lease/raw/lookup host checks and the5774610 parser/skip comparisons pass
against the full tree. This remains outside Android prebuilt inputs and is not a
complete dispatcher, network backend or flashable ROM.
