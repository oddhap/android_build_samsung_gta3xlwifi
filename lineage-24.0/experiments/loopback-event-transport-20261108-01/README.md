# Genuine loopback-event consume transport

Private NetpolicyLease::readLoopbackEvents consumes the real authenticated kernel
queue using32B transfer/40B frames. It checks primitive feature128, bounded coherent
metadata, exact head/contiguous sequence, record result/reserved/self-identity and
monotonic actual loss counters. Per-event loss can precede a newer metadata total;
those counters are deliberately tracked separately. Timestamp order is not assumed:
producers can timestamp on different CPUs before the queue lock. Lease close resets
cursor state, and a new lease may start at any actual queued head sequence.

All storage is allocated before consumption. Entire batch validation precedes any
caller output. Uncertain consumes, including EINTR or malformed acknowledgements,
are never retried; the lease closes/rearms and no batch publishes. Actual empty
queue returns real empty metadata, not a substitute metrics source. A sole backend
owner must serialize reads with policy transactions and propagate a read error to
its readiness state; no worker, Binder callback or global readiness is supplied.

Host02 passes132 cases plus696 LNA and90 UID transport regressions. Tests cover
malformed metadata/frames, duplicate/gap/wrap sequences, loss-counter differences,
backwards timestamps, pre/post-consume errors, reset/reopen, appends during consume,
and16 simultaneous readers delivering each of512 frames once. Host01 passed the
same132 assertions but its guessed minimum160 report guard failed; host02 corrects
that test-harness guard. Actual Android17 ARM64 CFI compile/partial link and ARM32/64 ABI checks pass
(loopback-event-transport-native-20261108-01 exit0): transfer32B,records40B,
transfer offsets8/16/24,event metadata16/24/32,GETc0206759. Prior UID24/8 and
LNA40/32 ABI checks remain.1243/17 before/after audits pass; TOP objects and kernel
UAPI hashes match. No production source/header/object or prebuilt is promoted.
