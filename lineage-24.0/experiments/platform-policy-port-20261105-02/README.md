# Current platform attribute ownership proposal

This follows proposal01 under the same owner clarification. In addition to
replacing old platform behavior, it retires old public membership/expansion
statements for attributes declared by the actual current platform CIL. Android17
already supplies these memberships; old version mappings must not reclassify
modern system types. Legacy declarations and compiler-private/versioned attribute
identities referenced by Samsung remain available. Samsung vendor CIL and all its
AV rules/assertions are still byte-identical to the reviewed parent.

The report and server statement ledger enumerate the exact retired statements.
The archived `stager.py` is the source used for this proposal. Strict compilation
still fails (secilc255/checker1), with **77 current-platform diagnostic blocks**.
Every other ordered compiler input and the compiler hash match proposal01 and
the parent; full 1,243-project/15-patch source audits pass before and after.
No -N compilation is performed. Runner exit0 is experiment completion only.

Attribute changes can affect complements and effective permission sets. Unchanged
AV statements alone do not prove monotonic permission narrowing. No effective
permission equivalence, security, boot, hardware or flash approval is claimed.
No image, active source, recovery or device change is made.
