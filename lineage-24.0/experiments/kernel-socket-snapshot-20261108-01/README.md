# One UID snapshot per private socket-table evaluation

The dedicated table now supplies one normalized actual socket UID to every raw
UID/appId match during that evaluation. Live inode ownership can change between
rules; A17 reads socket UID once before evaluating its owner program. Re-reading
that UID for each separate xtables match would mix identities. The internal
policy_uid API lets the enclosing socket-stage caller reuse its already captured
UID for owner, LNA, loopback and accounting decisions. The convenience entry point
captures a real UID itself within the same held-gate RCU drain domain.

The per-CPU context is protected across the complete evaluation with bottom halves/
preemption disabled. It is keyed to the exact skb pointer, saves/restores a nested
context, and never changes inode UID, socket metadata or packet ownership. Raw
matching on another skb or outside the private evaluator retains original live
UID/overflow semantics. Only the private ordinary context normalizes65534 to0.
The caller-protected supplied full socket and L3 cursor are still bound/restored.
No global netfilter hooks or packet attachment are introduced.

61 host assertions/864 grammar comparisons pass, including the actual modified
qtaguid getter: ownership changes during evaluation, another skb/clone observing
live ownership,65534 normalization only inside context, deferred caller UID,
nested evaluations and complete restoration. CPU/RCU/socket/table execution is
modeled; actual per-CPU and preemption code is compiled by the full kernel build.
Existing raw/metered and parser regressions use explicit outside-context fixtures;
the real context/getter integration is compiled in this dedicated test.

kernel-socket-snapshot-build-20261108-01 exit0 at19:18:53UTC Nov8:
Imageaa6262014445dba308221c1653b537c6ac9721055897aa7801da7c6221571364,
configfac42 unchanged. All60354 candidate/60331 protected kernel files and1243/17
Android projects/patches agree before/after. Gator118/KUTF43 imports match. Actual
ARM64 qtaguid object disassembly contains the real context-lookup call; no runtime
stub is used. Complete prior regressions pass. No image promotion, hardware packet
test, complete owner semantics or network readiness. Private-root bootstrap,
atomic multi-table transactions and correct socket-hook ordering remain required.
