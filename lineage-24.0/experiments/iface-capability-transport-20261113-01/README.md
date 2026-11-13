# Interface primitive admission through the real lease

`NetpolicyLease::requireIfaceAccountingPrimitives()` requires registered producer
bit 0x400 and compiled dual-stack DROP-correction bit 0x800. Either missing bit,
query/protocol error or unsupported old kernel fails closed. EINTR is retried for
this read-only query. The method does not open another FD, change a released
state, install rules or publish networking readiness. Other policy primitives
must still be checked by the complete owner.

Forty host cases pass, including independent missing bits, older capability
sets, errors/zero errno, retry, concurrent queries, retained single-FD identity
and released-state preservation. Both the new and prior generic four-state path
pass 994 regression checks. All twelve actual sources compile with Android17
ARM64 netd CFI/LTO flags; partial ELF link, seven exact kernel UAPI bindings,
real ARM32/ARM64 layout checks and 1243-project/17-patch audits pass. These are
syscall fixtures and static build evidence, not device or full netd execution.
