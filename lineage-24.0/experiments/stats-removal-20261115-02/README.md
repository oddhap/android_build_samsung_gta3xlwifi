# Durable UID cleanup and initial statistics admission

Inactive Java-only delta over terminal-abort-20261115-01. All native sources,
14 append-only AIDL methods, kernel headers and native prerequisite outputs are
exactly unchanged. No selected source, kernel, vendor image or policy promotion.

The actual consumer persists a version2 complete-state intent containing the
UID, generation, active epoch and journal-revision nonce before native RPC13.
Only an exact real kernel COMPLETE receipt allows local raw/adjusted/tag state
removal and a durable cleared-intent amendment. Completed recovery confirms the
cached request without repeating native deletion; counters created for a reused
UID survive. Proven live-session ESTALE/EBUSY clears only an unstarted intent,
preserves statistics and returns the rejection without refreshing/retrying a
possibly reused UID generation. Uncertain transport errors abort the exact
current native owner through RPC14. Unknown/PREPARED cold intents remain blocked,
with no blind replay or assumption that HOLD freezes ingress counters.

Initial publication waits for actual protected-directory journal validation.
The factory calls policy admission after releasing its existing data lock.
Private NSS construction skips actual BPF maps and SkDestroyListener: the real
7151 socket-owned kernel tags retire on final socket release. Dump paths expose
real kernel receipts and errors. NSS retires recorder/cache state per confirmed
UID; a later failure preserves that UID's history without retaining the baseline
of a UID whose native counters were already reset. Stock routing is preserved.

Validation:

- stats-removal-native-20261115-02: all12 actual sources compile against original
  A17 Connectivity SDK classpaths; native14-method prerequisite files remain
  byte-identical;1243 projects/17 exact patches pass audits before/after.
- stats-removal-host-20261115-02:62 durable transaction/fault checks, including
  lost mutation reply, pre/post-store faults, completed recovery, PREPARED,
  conflicting/missing history, version1 decoding and no mutation replay.
- stats-admission-host-20261115-02 replays those62 checks and prior1467 client,
  61 poll,327 consumer,13 factory,26 TrafficStats,7 cleanup,29 receipt and15 abort
  checks, then18 actual backend admission/collector and NSS method-body checks.
  Factory policy admission is checked outside the actual data lock. Batch
  partial-failure ordering executes the extracted unchanged real NSS method.

Host Android/store/Binder/kernel/service collaborator boundaries are explicit
fixtures. Actual A17 NetworkStats, UnderlyingNetworkInfo and pinned VPN arithmetic
are preserved. This does not test the complete Android service constructor or
physical device execution. Admission host01 exposed a missing Pair.create in a
host fixture; host02 supplies the original framework fixture, without source
weakening. Removal host01 had a wrong historical report path and did not compile.

Remaining work includes loopback event delivery, dedicated CLAT raw sockets,
Soong/APEX source and jarjar descriptor composition, explicit snapshot/kernel/
policy selection, full ROM build and installer/encryption/partition validation.
No flash-ready package exists.
