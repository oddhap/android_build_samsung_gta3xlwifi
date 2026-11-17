# Native CLAT registration and optional aconfig containers

Snapshot20 physically reaches the Android17 boot animation, genuine platform and
mainline flag storage, and AdvancedProtection startup. Its next system_server
abort is in native ClatCoordinator registration (BuildId
`47de4be5bebe3135b31ddaef31404de2`), before the existing userspace CLAT owner is
constructed. Private device evidence is represented by hashes in the sanitized
snapshot20 physical report.

Snapshot21 selects the same read-only product backend during JNI registration.
The userspace path still checks the real clatd directory/binary ownership, modes
and SELinux contexts and aborts on any failure. The BPF path retains its original
program/map checks. Actual packet translation and privileged socket accounting
remain in the existing Java/daemon/provider implementation. No BPF object,
readiness state, kernel capability or successful packet operation is synthesized.

The second change records only successfully initialized platform flag containers
for the final override pass. A vendor with no aconfig files was already skipped
on input, but the old final pass still attempted it and failed. Corruption,
staged-OTA failures, property errors and registered-container failures propagate.
Genuine compiled flag values and services are retained.

The regression executes the original and changed production control-flow bodies
with explicit syscall/property/storage-manager fixtures. It reproduces both
original failures, then passes79 native verification cases and197 Rust bootstrap
cases. It does not validate kernel syscalls, real aconfig parsing or translation
on hardware. Complete production compilation and packaged binary checks follow.
Policy, cache selection, kernel, vendor, userdata and recovery are unchanged.
