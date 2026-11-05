# Port platform classifications embedded in old vendor metadata

This isolated proposal follows 02 under the owner's November5 clarification:
Android17 and Samsung vendor assertions remain required; the obsolete Android11
platform component is ported explicitly. Old platform behavior is replaced as
documented in 01. No strict checker option is disabled.

Samsung vendor CIL also contains old shared attribute lists with platform types.
For attributes declared by actual current platform policy, this proposal removes
members whose concrete platform name is declared by current platform CIL (including
the corresponding API30 symbol). Android17 supplies platform classification.
Vendor-private and legacy-only members remain, as do all non-membership statements
byte-for-byte, including every vendor allow/allowx/neverallow/neverallowx. Only
positive flat lists are accepted; expressions require separate review.

The ledger records **54 changed assignments / 2,371 removed platform symbol
occurrences**, with original statements and retained members. All 131 vendor
neverallow and two neverallowx statements remain textually unchanged. Current
platform CIL, every other ordered compiler input and the compiler hash match the
parent. Complete 1,243-project/15-patch before/after source audits match.

Strict compilation still fails: **72 current-platform diagnostic blocks** versus
319 initially, 79 in 01 and 77 in 02. Secilc255/checker1 remain failures;
runner0 denotes a completed experiment. Membership changes can affect complements;
unchanged AV text does not establish permission equivalence or monotonic narrowing.

Remaining conflicts include legacy broad access to BPF objects, property ownership,
MLS compatibility, data directories and platform services. Some current platform
allows still conflict after linking vendor memberships; deleting vendor allows
alone cannot repair all of them. Do not add vendor domains to bpfdomain or fake
BPF support merely to make policy compile. Complete verbose diagnostics are
recorded separately for the next semantic review.

The server artifact contains exact copies of the tools used, full original/after
audits, statement ledgers and compiler inputs/hashes. No staged metadata is in
active Android source, snapshots or the vendor image. No precompiled policy/cache
hash, key, kernel, recovery or tablet is changed. Effective permission coverage,
labels, cache invalidation, boot and runtime remain unvalidated; no flashable ROM
or security approval is produced.
