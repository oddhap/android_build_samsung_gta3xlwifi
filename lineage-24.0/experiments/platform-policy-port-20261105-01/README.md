# Isolated Android17 platform behavior with legacy symbol ABI

On November 5 the owner clarified: retain Android17 platform and Samsung vendor
assertions, and port the obsolete Android11 platform component. This supersedes
the earlier assumption that every frozen Android11 platform assertion must remain
an additional platform contract. It does not authorize disabling strict checking.

This first proposal retains every legacy declaration, attribute expression,
expansion setting and roletype byte-for-byte. It replaces old platform behavior
with the unchanged actual Android17 platform CIL, already in the ordered compiler
inputs. The old public fragment's 4,461 allow, 137 allowx, 1,657 neverallow,
168 neverallowx, 67 dontaudit and one auditallow statements are explicitly retired;
their original statements, line locations and hashes are retained in the server's
`superseded-platform-behavior.json`. This is a documented platform replacement,
not a claim that these historical assertions remain active.

Samsung vendor CIL is byte-identical to the reviewed namespace/capability-narrowing
parent: all 131 neverallow and two neverallowx statements remain. Every Android17
platform assertion and every other compiler input is unchanged. There is no -N
compile. Strict compilation still fails (secilc255/checker1), with **79 current
platform diagnostic blocks**, down from 319. Experiment runner exit0 means the
experiment finished, not that policy passed. Complete 1,243-project/15-patch
before/after source audits match.

`stager.py` is the exact first-run source, hash verified against the report. It
imports the common tokenizer from the tools directory when reproduced; the main
tool now supports this original mode plus a subsequent current-attribute mode.
The staged public fragment hash is
`7bb0c35a0aa415c5b19daf9bf41dc5939d47ddb30a79791ae4414ca288ad57dc`.
No active source, image, cache hash, kernel, recovery or tablet is changed. This
does not validate effective permission coverage, labels, boot or hardware.
