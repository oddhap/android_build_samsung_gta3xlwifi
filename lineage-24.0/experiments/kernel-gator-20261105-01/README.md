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
