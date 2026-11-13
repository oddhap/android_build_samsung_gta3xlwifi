# Require actual packet accounting before producer startup

The existing single-lease four-state accounting owner additionally requires both
storage and compiled packet producers before its first firewall operation. Old
kernels or either missing bit fail closed. Read-only feature EINTR retry retains
the same descriptor/mutex and never releases or publishes state. The generic
owner mode is unchanged. Primitive storage I/O remains independently available.

No new Binder/Java routing, lifecycle polling, owner forwarding, source/prebuilt
selection or global readiness is provided. Actual packet producer integration
and strict current policy remain separate prerequisites. No flash candidate.
