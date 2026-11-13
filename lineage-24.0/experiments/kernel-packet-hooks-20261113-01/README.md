# Isolated UID/app packet producer hookup

Actual receive and output functions use one socket UID/tag snapshot for policy
and accounting. Receive DROP, including the held gate, is counted; dropped output
is excluded. Parser-fail PASS still counts. CLAT exclusion applies only to output.
System DNS billing remaps to the normalized socket UID while preserving its tag.
Metadata errors report real accounting loss and retain the security verdict;
capacity failures never change verdicts. Existing interface DROP UNDO remains.

The actual store plus actual packet functions are compared with the pinned
Android 17 bpf_traffic_account function (BPF verifier assembly lowered only to
its exact C integer mask). Parser/policy/metadata are fixture inputs; storage,
identity handling, accounting placement and GSO arithmetic are actual source.
Source outside the two packet bodies and one helper/include is byte-identical.
The runner checks compiled ARM64 reachability of record/loss for both directions,
all earlier regressions, modules/config and complete protected/Android audits.

The existing private feature bit12 still proves STORAGE ONLY. No native admission
for compiled hooks, production service routing, installed rules, statistics
lifecycle or global networking readiness is claimed. No source/policy/prebuilt
selection or flash candidate.
