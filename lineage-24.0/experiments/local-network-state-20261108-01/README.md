# Canonical LNA state

Private two-table value, preserving actual BPF prefix semantics by clearing all
ignored suffix bits before emitting strict sorted unique wire snapshots. Upsert
normalizes equivalent prefixes; ambiguous duplicate full-image inputs reject
before either table changes. Both tables independently enforce1000 entries.
Queries implement query-prefix-bounded longest match, with found=false/allowed=true for missing
entries; they are value queries and do not apply UID/permission packet decisions.
UID removal prunes that UID's host keys (at least32 UID bits); broad multi-UID
prefixes remain. Actual Java wildcard/interface64 and specific-host192 constructors
are hash bound; the stale upstream comment implying all host keys are192 is not
used as the contract.

Host04 passes27096 checks and144246 oracle comparisons. The real selected kernel
Patricia insertion/lookup/canonical C is compiled as the full192-bit oracle;
bounded queries additionally use independent bit-by-bit scanning. All193 prefix
boundaries, sorted snapshots, duplicate canonical collisions, capacity and UID
pruning are covered under fatal UBSan. Host01 failed a test's incorrect literal
Java assertion (constructors use32+32 and32+32+128); host02 lacked a u16 fixture;
host03 passed all checks but an overly exact comparison-count guard failed.
Host04 corrects these test-harness issues without changing the state source.

Native ARM64 CFI compilation passes, with all1243/17 Android source inputs matching
before/after (local-network-state-native-20261108-01 exit0). No kernel packets,
production source/object replacement, complete backend or readiness publication.
