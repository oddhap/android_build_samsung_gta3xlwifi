# Explicit private-table checked chain I/O

CheckedUidChains adds a typed Filter/Socket selection; default Filter behavior is
unchanged. Socket operations target only g24sock and accept the nine UID chains
and two owner roots. Metered/data-saver names, owner/slow-appId UID selectors and
REJECT/data-saver targets are rejected before I/O and during readback. No arbitrary
table-name input, root-chain mutation or foreign-table text replay is introduced.
Actual ordinary compiler output uses the permitted read-only matches and silent
DROP, not REJECT. Every write still requires exact readback and verified rollback;
uncertain rollback returns EUCLEAN for the sole owner to quarantine.

59 private-table scripted I/O/parser/compiler checks and84 original filter cases
pass with fatal UBSan. Both families, partial writes, bad readback, invalid
namespace/targets, invalid typed table values and complete eleven-chain ordinary
programs are checked. socket-chain-io-native-20261108-01 passes four-source actual
Android17 ARM64 CFI compile/link and1243/17 before/after audits. Kernel header binds
the exact g24sock name. This is not private-root bootstrap/activation, a complete
multi-table transaction, packet/runtime enforcement or a readiness owner.
