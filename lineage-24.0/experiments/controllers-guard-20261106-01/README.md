# Isolated atomic root-chain guard preservation

The actual Android17 Controllers exclusive-chain setup flushes the parent before
adding children. For the existing gta3xlwifi legacy-networking opt-in, this patch
adds the unconditional guard/DROP immediately after that flush in the SAME filter
transaction for INPUT/FORWARD/OUTPUT. Other tables, nonexclusive chains and
nonlegacy products retain exactly the original commands. Shared OUTPUT setup
already retains the existing guard; the explicit hook verifier still checks its
first position. No startup mode, property value or readiness signal is changed.

The complete owner must hold the real private lease before Controllers init.
This source patch alone does not establish that owner/startup ordering or complete
networking. It is deliberately not applied to TOP or Android images.

960 actual-function differential cases with fatal UBSan compare old/new command
builders across products, tables, root names, existing children, target families
and return codes. Properties, chain lookup and execution remain host fixtures.
The candidate then compiles with the actual Android17 CFI command, replaces only
Controllers.o in an isolated complete 18-object libnetd_server archive and links
the WHOLE actual ARM64 CFI netd binary with original strict flags. Dependencies
are identical; production objects/archive/binary are unchanged. Full 1,243-project/
17-patch source audits pass before/after. No netd process or rule is executed.

Native attempt01 stopped on an incorrect verifier assumption of more than20
archive objects. It is preserved, including successful source audits. Attempt02
binds the exact18 graph inputs and verifies their ordered names against the actual
original archive, then completes all compilation/archive/full-binary checks.
Real boot/restart/packet behavior and full legacy networking remain unvalidated.
