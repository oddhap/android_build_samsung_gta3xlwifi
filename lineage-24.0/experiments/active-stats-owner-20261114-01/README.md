# Active statistics counts under the sole owner

NetpolicyLease reads the genuine active snapshot on its existing authenticated
FD. It requires compiled capability bit15, resets all wire output fields before
EINTR retry, validates metadata and sorted counter keys, and publishes output only
on success. SocketPolicyProjection reads the current epoch and active rows under
its complete policy/statistics mutex, excluding concurrent owner SWAP/ACK. It
returns actual total/per-chargeUID row counts with epoch, sequence and real loss.
The count is not a tag/socket count, a completeness claim or tagging authorization.
A future tag operation must check permission/budget and write its transport under
the same owner mutex, not reuse this result as a durable grant.

The real owner/transport passes 3,250 fixture cases, including the previous 3,186
and 63 new checks plus the enclosing regression assertion. Every five new I/O
points is tested on both sides of failure. Invalid arguments preserve publication;
unsupported kernels, uncertain I/O or malformed payloads quarantine all states.
Generic/unpublished use fails without stats I/O. Loss is explicitly forwarded.

active-stats-validation-20261114-01 passes startup29, guard960, packet transport99,
runtime transport71, all sixteen actual ARM64 CFI sources and whole netd linking
with unchanged dynamic dependencies. Actual ARM32/64 wire/UAPI checks and all
1,243-project/17-patch before/after audits pass. The full matching kernel passes
separately. Earlier failed fixture attempts remain immutable.

The actual generated AND compiled Java flags accessor enables UID migration in
this checkout. tagging-contract-20261114-01 binds that evidence and executes the
actual A17 budget guard at 81 boundaries: perUID500, total4500, strictly greater
than the limit rejects (equality allows). No flag is changed. This is build/source
evidence, not a claim about a running tablet or a completed tagging provider.

Actual authorized tagging/session initialization, mainline provider callbacks,
complete Java/Binder initial frames/delta ordering, statistics persistence/ACK and
event delivery remain unfinished. No kernel/source/policy/prebuilt is selected;
no BPF objects, readiness signal, flash candidate or hardware claim is produced.
