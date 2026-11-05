# Retire obsolete MLS escape and narrow old vendor access

This isolated proposal starts from platform-policy-port-20261105-03. It removes
seven old vendor allow statements (six distinct rules, including two identical
dumpstate-to-vold Binder grants). Android17 forbids these vold debugger/Binder,
shell-file execution and setupwizard-property writer operations. Read/FD/signal
grants outside the exact reviewed statements remain unchanged.

It also ports the old platform API30 compatibility fragment: the mlsvendorcompat
membership assignment and its four app-data allow rules are retired. Android17
explicitly forbids any domain using this obsolete MLS escape. Current platform
MLS constraints, category handling, domain labels and all assertions are unchanged.
Actual vendor app seapp/MLS labels and behavior still require runtime validation.

Strict diagnostics decrease **72 -> 67**, with five resolved and no new assertion
diagnostic identities. Secilc255 remains failure. Full assertion/constraint
inventory comparison retains **all 5,917 records**, adds no AV grant statement or
permissive declaration, and records eleven removed allow statements across the
two input files. All other ordered inputs and compiler hashes are identical.
Full 1,243-project/15-patch before/after source audits pass and match.

Runner exit0 means experiment completion, not security approval. Two initial
attempts (legacy-policy-access-20261105-01/02) stopped in the new script's input
selection guards because system and system_ext share compatibility basenames.
They did not create staged policy or invoke the compiler; their logs/audits remain
on the server. The successful tool selects the system fragment by its complete
audited build-output path and checks its exact digest. Existing labels are reused
neither for retries nor output overwrites.

Exact tool sources, changed-input patches, removed-statement ledger and reports
are archived here and on the server. No -N compile, active source edit, image
integration, cache hash change, signing, flashing or device operation occurs.
