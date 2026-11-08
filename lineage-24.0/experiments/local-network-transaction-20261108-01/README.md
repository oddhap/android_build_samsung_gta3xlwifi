# Combined LNA / UID / rule transaction

The private backend gates traffic, verifies all six root guards and captures
both-family rules plus coherent LNA/UID images. Canonical values are validated
before any I/O. Both rule families and guards are verified before any image SET.
LNA is SET/read back before UID is SET/read back LAST, as root NoInternet may deny
future control sockets. No firewall I/O occurs after either SET. Cache storage is
prepared before writes. The sole owner/mutex protects the earlier verified LNA
image while committing UID state. Release follows complete primitive verification.

Before-SET rule failures restore/verify both families and prove both old images
unchanged; only a prior complete LNA commit permits resuming. Any SET/readback or
release uncertainty closes the lease and quarantines, without post-SET firewall
rollback. Entering this mode prevents older methods from omitting LNA state.

Host03 passes62 cases plus696 LNA transport/90 UID and55 previous UID transaction
regressions. Fault cases include partial rule writes, both ambiguous SETs, table
readback mismatch, external cached-state drift, final release error, and root
NoInternet. Host01 exposed a missing LocalNetworkState link dependency in the
legacy test harness; host02 exposed a misleading-indentation warning in a fixture.
Host03 fixes those test harness issues; transaction source is unchanged.
Actual Android17 four-source CFI compile/link/audit passes;1243/17 Android inputs
match before/after (local-network-transaction-native-20261108-01).
These are UID/LNA primitives, not complete networking or Binder startup.
