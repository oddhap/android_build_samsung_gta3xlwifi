# Independent per-user appId packet match

Prerequisite: kernel-netpolicy-20261106-01. The separate `gta3xlwifi_appid`
revision0 ABI matches a bounded inclusive appId range using socket UID modulo
100000. It reuses the actual Samsung qtaguid INPUT socket lookup/refcount
contract. Missing/default overflow UID is normalized to root, matching the
inspected Android17 accounting path. Only initial-user-namespace IPv4/IPv6
INPUT/OUTPUT rules are accepted. Owner revision1, its initcall, statistics and
socket tagging code remain unchanged; no unknown owner flag is repurposed.
A separate builtin initcall registers the new match. QTAGUID is Kconfig y/n.

22 actual-function namespace/range/socket-reference/registration cases and343599
comparisons against the extracted actual Android17 is_system_uid predicate pass
with fatal UBSan. Socket lookup, references and namespaces remain fixtures.
The first host attempt failed because a fixture counter shadowed libc puts;
only the fixture name was changed. The source component was unchanged.

The full isolated Image/module build completes exit0. The actual final vmlinux
contains both owner and new appId initcalls. All118 Gator/43 KUTF imports pass
against the actual exports. Candidate60335/protected60331 tracked-file audits
match before/after, and full Android1243-project/17-patch reference audits pass.
Exact configuration remains fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea.
Image SHA256: a51be5f805d6169410ae29a77f1d3e7d3717ec29bb98fce09cf6ecfb48d78a39.

No Android prebuilt input, policy selection, rule or hardware is modified.
Userspace registration/rule construction and complete Android17 networking
integration remain required. Native packet/lookup/RCU behavior is untested.
This is not a flash-ready ROM or a declaration of BPF/network readiness.
