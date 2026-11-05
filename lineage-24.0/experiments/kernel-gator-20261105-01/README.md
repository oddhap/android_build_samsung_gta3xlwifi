# Bounded interrupted-register Gator stack tracing proposal

Isolated prerequisite: kernel-capabilities-20261104-01. No Android prebuilt is
updated. The original Samsung source/output, exact config and firmware remain
protected by the build runner's complete tracked-file audits.

ARM64 modules cannot link the unexported walk_stackframe entry point. This
proposal implements the already-declared save_stack_trace_regs API using the
existing bounded collector and unwinder, with the interrupted frame pointer,
stack pointer and program counter, current task-stack lifetime, skip/count and
function-graph state. The GPL export allows Gator to use that API on this kernel.
Gator ignores the terminal ULONG_MAX marker before looking up module ownership.

The host test extracts actual collector/consumer function bodies and covers 336
bounded combinations plus null-register, unavailable-stack and sentinel controls,
with function-graph state both enabled and disabled. The unwinder and task/module
operations are host fixtures; this does not validate native interrupt unwinding.
The full kernel/module build and actual module import-CRC audit remain required.
No module installation/load, release signing, flashing or boot approval occurs.

Completed November5: the full Image and KUTF build succeeded; an incorrect
external-module invocation then stopped the runner. The preserved failure is
`kernel-gator-build-20261105-01` exit2. `resume-modules.sh` uses the proper in-tree
`drivers/gator/gator.ko` target and completes `kernel-gator-modules-20261105-02`
exit0, without changing source/config/Image. Static version checks pass all
118 Gator and 43 KUTF imports against the actual candidate exports. Complete
60,331-file candidate/protected-source audits remain identical.

Image SHA256: `9fc9c3cf0d46d6f62e810a1b598a6bf0c6a0465ca923fa953bd6eed318270d92`.
The original exact config digest remains `fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea`.
`strict-kernel-policy-20261105-03` completes exit0 with both final strict policies:
zero independent Android17 libsepol differences, 8,192 queries, 6,291,456 AVC and
3,145,728 packet fixture evaluations per profile. Full Android and kernel audits
match before/after. No native cache/concurrency, interrupt, module-load or boot
validation is claimed. Incomplete networking prevents prebuilt promotion.
