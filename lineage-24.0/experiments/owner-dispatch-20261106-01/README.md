# Ordinary UID packet dispatch portion

Adds two owned chains g24_owner_in/out with raw appId core RETURN, actual A17
owner-skip predicate RETURN, nine bounded owned child calls, then RETURN.
Only BACKGROUND's call is conditional on the non-loopback predicate; all other
ordinary rules still apply on interface1. Membership selectors remain raw UID.
Checked I/O accepts only fixed numeric child1..9 targets from these two roots,
requires included child images, forbids cycles by construction and rejects
foreign/leading-zero target aliases. No arbitrary target or command text is replayed.
UID transaction compilation now includes all14 chains with aggregate limits.

13 cases and12582912 comparisons pass against ACTUAL A17 bpf_owner_match,
skip_owner_match and bit expressions: all512 config/membership combinations,
six raw UID views and eight direction/protocol/flags/interface contexts. VPN/IIF
memberships and ingress-discard entries are absent in this ordinary-only scope;
packet metadata and maps are fixtures, not actual kernel packets. The independent
interpreter implements the typed graph, core and packet selectors separately.

The eight-source transaction fixture03 passes164 cases, including all14 ordered
chain readbacks, rollback/error/publication/concurrency and foreign-call rejection.
Fixture01 failed a test-only string range-loop warning;02 also passed164 but had
a stale seven-source print label;03 fixes that label without product changes.
The existing checked84 and metered51 plus1248 A17-expression regressions pass.
All eight actual C++ sources compile/combine with Android17 ARM64 netd CFI flags,
actual IptablesRestoreInterface and complete1243-project/17-patch source audits.

No roots are attached and no callback or network readiness is supplied. Complete
VPN/interface policy, DNS/CLAT tagging, mandatory independent LNA/loopback protection,
startup/provider ownership and device execution remain required. The owner-skip
RETURN belongs only to ordinary-owner evaluation, not independent security paths.
Before promotion, output interface selection must use the current route after
mangle rerouting rather than a potentially stale netfilter hook output pointer.
