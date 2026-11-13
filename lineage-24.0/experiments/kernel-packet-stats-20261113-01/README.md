# Isolated packet statistics storage primitive

Real bounded UID/tag banks (5000 rows each), app UID counters (10000) and
counterset controls (20000), matching the pinned Android 17 capacities.
Uses actual Linux 4.4 GSO metadata with Android 17 UID/app arithmetic.
The existing privileged owner file/TGID lease authenticates every control.

Bank selection and producer writes share one spinlock. A CAS swap freezes the
old bank; reads do not consume it. Explicit epoch-bound ACK clears it and is
idempotent. A swap user-copy fault can follow a committed transition: query
state to recover; do not blindly replay. Pending banks block UID deletion.
UID deletion here affects statistics/counterset only, not socket tags.
Loss fields count failed accounting attempts, never fabricated traffic totals.

Private feature bit 12 proves storage/control only. It is unrelated to SELinux
policycap 12. No packet hooks, production rules, Android service routing,
network readiness, policy input selection or prebuilt promotion is included.
No flash candidate exists. The build runner uses fresh source/output, exact
prerequisite hashes, strict capability rejection and full source audits.
