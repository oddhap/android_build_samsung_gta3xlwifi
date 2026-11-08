# Correct untagged CLAT accounting-UID fallback

This explicit corrective patch supersedes the earlier egress prototype's
assumption that CLAT bypass always requires a tag record. Actual A17
bpf_traffic_account sets statsUid to normalized actual SOCKET uid when its cookie
has no tag record, then tests statsUid==AID_CLAT. A tagged socket uses its recorded
stats UID instead, so a raw socketUID1029 tagged to another UID is not exempt.
The current process UID never supplies this decision. The held gate still wins.
DNS still requires the exact recorded tag/UID pair. Ordinary LNA uses raw current
socket UID and remains unchanged.

Host02 compiles the actual A17 traffic-account prefix (source hash bound) as a
CLAT oracle and passes100 egress cases, including48 UID/tag/family combinations,
plus51 receive/5632 parser comparisons. Host01 exposed an unused tag-variable
warning in the extracted prefix fixture; adding a void-use preserves the verbatim
reference body. No kernel source change was needed after the corrective patch.
Original IPv4/IPv6 output bodies, multicast callbacks and one-consumption ownership
checks remain. Full kernel/modules/source audits pass (kernel-egress-clat-build-20261108-01
exit0 at16:52:50UTC Nov8). Image6bf528918974c70b27ff3a43c8d9c5e852630c68b2741ea5dfbd310d32b579d9,
configfac42 unchanged;60349 candidate/60331 protected tracked hashes and1243/17
Android projects/patches match before/after. Gator118/KUTF43 imported versions
match; full legacy regressions and new100/48-oracle cases pass. No UAPI/xtables
change; preceding actual77 registrations/archive/link remain applicable. No promotion.

Previous egress51-case/kernel67ec0b37 results remain historical component evidence;
their untagged rawCLAT expectation is explicitly superseded here. No claim of
complete UID/VPN/IIF/loopback/metrics/accounting or global networking readiness.
