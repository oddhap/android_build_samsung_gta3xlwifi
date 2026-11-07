# Combined committed UID value publication

Extends the isolated UidPolicyTransaction with an explicit full initial UID
policy + seven-bit permission value. All mutations/queries share its mutex.
Later ordinary updates retain the committed permissions and call the combined
real rule/image backend. Permission changes commit the complete UID state too.
UID removal removes both ordinary memberships and the permission entry together.
Only verified complete kernel commit/release permits publishing both new values.
Any kernel uncertainty withdraws both values, closes the lease and requires an
explicit restart/full replacement. Unpublished permission queries return EAGAIN
without changing caller output. Local invalid or oversized values preserve the
old committed state without kernel I/O. No allocation for values occurs after
the real backend has released its gate. The plain historical UID-only path stays
an isolated primitive and does not advertise complete networking readiness.

Host82 cases pass with actual nine-source policy/compiler/encoder/transport/
backend code, fatal UBSan and syscall/rule tables. Covers preserving permissions
across ordinary changes, explicit initial state, removal, invalid/oversized images,
initial/later both-family failures, ambiguous SET, withdrawal and explicit recovery.
An actual contended reader observes the new value only after a paused V6 update
finishes and permission SET/readback/release succeed. Old164 UID publication
regressions and90 transport tests pass with the same candidate sources. The old
regression tool retains its historical eight-source stdout label; its recorded
compile command now also includes the permission value dependency.

The actual nine-source ARM64 Android17 CFI compile/link-to-object and complete
1243-project/17-patch before/after audits pass. Tool's inherited eight-dependency
scope label is historical; report compile_commands contains all nine actual
sources and verifies new publication symbols. Full netd linking, Binder/Java/DNS
registration and mandatory LNA/loopback/events/VPN/IIF/CLAT packet behavior remain.
No active Android inputs, flags, images or device state changed. Not flash-ready.
