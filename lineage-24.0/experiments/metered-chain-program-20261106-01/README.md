# Typed metered deny, allow and Data Saver programs

Three owned chains implement the actual Android17 xtbpf predicates: raw socket
UID user/admin deny union without a core exemption; raw appId core exemption
(including literal65534 normalization), HAPPY raw UID membership, then Data Saver.
Only consecutive memberships merge. A goto reaches the included one-rule Data
Saver chain; conditional targets, missing helpers and cycles are rejected.
The deny verdict is builtin REJECT with its family-specific default ICMP mode.
Checked readback accepts only the actual canonical --reject-with default for the
selected family; alternate modes and wrong-family output are rejected. Typed
selectors preserve the existing owner lookup separately from raw socket UID.
All compiler and encoder limits apply before replacing caller output.

Host fixture03 passes51 cases and1248 comparisons with extracted actual A17
allowlist_xtbpf/denylist_xtbpf expressions. Raw UID/core/overflow, secondary-user,
user/admin union, Data Saver and HAPPY interactions are covered. Both-family I/O
fixtures cover numeric uint32/range boundaries, exact REJECT readback, wrong-family
and foreign flags/targets, failed acknowledgements after possible commit, verified
rollback and EUCLEAN on unverified rollback. First fixture attempt failed a C++
warning in the oracle wrapper; explicit enum casts fixed the test only. Attempt02
passed;03 repeats with corrected header documentation. No product source changed.

Existing checked-chain84 cases and ordinary35 plus1048576 actual A17 expression
comparisons pass on the extended sources. Native01 compiles/combines four actual
C++ sources with real Android17 netd CFI flags and complete1243/17 source audits.
Native02 binds the final comment-only header correction. No complete netd link,
actual rules, packets or device execution is claimed.

Parent wiring remains REQUIRED: metered deny precedes allow; HAPPY's parent must
use goto semantics so an allow RETURN cannot fall through to an old Data Saver
fallback. Ordinary packet/core/ESP/TCP/interface/VPN/LNA dispatch, startup ownership,
Java/DNS/provider integration and verified attachments remain incomplete. These
sources are inactive and publish no callback or network readiness.
