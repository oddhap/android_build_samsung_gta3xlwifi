# Combined LNA / UID value publication

A private frontend accepts explicit initial ordinary policy, UID permissions and
LNA state, then serializes all readers/mutations across the real backend update.
Only complete rules/LNA/UID readback and release publishes all three values.
Existing ordinary or permission-only API calls retain the full LNA state once
entered. UID removal also removes that UID's host exceptions. Local invalid input
preserves the committed state without I/O; kernel/ack errors withdraw all values,
close the lease and require explicit restart/full state.

Host02 passes106 cases plus696 LNA/90 UID transport and82 previous publication
regressions. Cases cover retained LNA through ordinary/permission updates, coherent
UID cleanup, ambiguous writes, errors with/without prior state and a paused writer
preventing reader publication until complete success. Host01's concurrency fixture
waited for a rule write while submitting identical rules; the real encoder correctly
skipped that write. Host02 submits a real rule change and bounds the fixture wait.
The publication source is unchanged. Ten-source actual Android17 CFI compile/link/audit passes;1243/17 inputs match
before/after (local-network-publication-native-20261108-01). No Binder, process startup or global networking-ready signal is
provided; packet metrics and other mandatory policies remain outstanding.
