# Android17 compiler oracle for property ownership before completion

The exact positive dependency graph is replayed in small noninstallable CIL
fixtures and checked by the real pinned Android17 secilc with strict neverallows.
The owned guard must compile; a concrete witness for each predicted unowned type
must produce exactly its own diagnostic. This independently checks both positive
and negative membership predictions over all 524 property types. There are 66
expected unowned types here; all compiler results agree. No -N flag is used.

This validates the replayed ownership graph, not runtime AV/MLS decisions, the
whole vendor policy, labels, properties on hardware or boot. Fixture binaries are
not installation policies. Exact source fixtures, compiler commands, hashes and
results are retained. Negative/unknown/cyclic graph dependencies are not guessed.
