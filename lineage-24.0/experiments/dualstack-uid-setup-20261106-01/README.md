# Explicit guarded UID-hook setup

Incremental prerequisite: dualstack-uid-chains-20261106-01. Default start remains
VerifyOnly. Explicit InstallMissing captures/validates all six actual root chain
images before any writes, refuses ambiguous/misplaced private matches, and inserts
only missing unconditional first guard/DROP rules. Existing root policies/rules
are retained byte for byte in ordered readbacks. Each family's insertions share
one actual iptables transaction. An already correct setup is read-only.

The lease stays held during/after setup. Failed acknowledgements can follow
commits, so partially installed guards remain in place and the owner lease is
closed/rearmed. A subsequent explicit setup rereads actual state and can finish
only missing insertions. No rule removal, networking-ready property, startup
service bypass or Android image selection is introduced.

90 actual-code host cases pass with fatal UBSan, including the prior transaction
suite, missing/mixed/already installed hooks, both-family failures before/after
commit, malformed setups and recovery on a new session. Host attempt01 failed
because a test macro treated a map initializer comma as an extra argument. The
fixture was parenthesized; component source was unchanged; attempt02 passes.
All three actual C++ sources compile with Android17 netd CFI flags and link as
one native ARM64 relocatable object. Complete source audits pass before/after.

This does not yet solve real netd restart integration. Controllers::createChildChains
flushes exclusive filter INPUT/FORWARD chains; the final legacy owner must retain
or reinsert the first guard in the same atomic transaction while rebuilding those
chains. Installing guards only after an unguarded flush is insufficient. An
initially held kernel bit does not block paths whose guard is still absent.
The complete startup owner must keep networking unavailable until all attachments
and backend features are verified. Real packet/RCU/FD behavior and the full
Android17 backend remain unvalidated. No source is applied to TOP here.
