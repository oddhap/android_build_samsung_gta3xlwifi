# Ordinary UID policy at real supplied-socket stages

Connects the private snapshot-safe table to the actual full-socket receive and
IPv4/IPv6/multicast egress wrappers. The shared RCU/held-gate domain encloses one
normalized UID sample, tag lookup, ordinary table evaluation and LNA/loopback.
A concurrent inode UID change cannot switch identity between these operations.
The supplied caller socket is used, preserving the unrelated skb owner and its
cursor. The evaluator cannot consume/free the packet; existing callers retain
ownership. Gate close/HOLD drains the complete decision.

On receive, ordinary DROP applies before the parser-gated LNA/DNS exception.
On egress, actual tagged/untagged CLAT accounting identity bypasses first, then
ordinary DROP precedes loopback/LNA and DNS. Unknown parser output cannot skip
ordinary policy. Metadata-unavailable paths remain explicit errors. Root bootstrap
and native complete image verification are separate prerequisites; no test image
or backend readiness is implied by this isolated hook attachment.

84 source-bound hook assertions pass with the actual parser/LNA/loopback code,
including DNS DROP/PASS, parser failure, CLAT tag/fallback, both socket families/
directions, UID mutation during tag lookup and table evaluation, unchanged packet
ownership, same UID for real LB events/LNA, and real pthread HOLD grace ordering.
The private table verdict is a DROP/PASS fixture in this test; the actual evaluator
and exact-skb snapshot are separately tested in socket-tables-host (65 assertions/
864 grammar comparisons). Earlier51/100 receive/egress,5632 parser,1797 loopback/
98304 A17 permission comparisons and all other kernel regressions pass. Legacy
LNA tests explicitly isolate private-table verdicts to PASS; this does not prove
full xtables packet execution or actual hardware behavior.

kernel-socket-owner-build-20261112-01 exit0 at19:35:10UTC November12:
Imaged260119d3c6b7e97705beaca8362486761c58df7f0953048b81abdd02eae74b4;
configfac42 unchanged. Actual ARM64 qtaguid disassembly contains both real private
policy calls. Full kernel/modules, Gator118/KUTF43 versions,60355/60331 source
files and1243 projects/17 exact patches before/after audits pass. No Android
prebuilt/input selection, SELinux assertion, signing, installation or device change.

Next: real VPN/IIF and ingress-discard semantics, complete atomic ordinary/private
and metered/filter transaction/attachments, authoritative startup/Binder/Java and
metrics delivery/accounting. Encryption/Keymaster rollback and installer/final OTA
gates remain beyond networking. This is not a flash candidate.
