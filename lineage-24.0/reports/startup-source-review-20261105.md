# Android17 legacy startup source review

The companion JSON pins eleven actual source/config files and six project revisions.
This is source review, not hardware or syscall/permission execution proof.

The Java app zygote calls `createProcessGroup(uid, getpid())`; the port routes it
to the actual cpuacct v1 hierarchy. The new Rust zygote currently calls `fork()`
(the upstream clone3 path is commented pending b/439747272) and its native child
calls `cgroup::create`. No selected zygote source calls `create_for_clone_into`.
The exported clone-into API therefore keeps its truthful `-EOPNOTSUPP` response;
there is no evidence in these pinned callers that this alone blocks app spawn.
The Rust service is disabled unless explicitly requested by its start property.
This conclusion must be reviewed again when upstream revisions change.

The actual kernel config enables `CONFIG_ANDROID_LOW_MEMORY_KILLER` and
`CONFIG_CGROUP_CPUACCT`. LMKD detects writable real lowmemorykiller minfree sysfs
and selects its in-kernel interface before attempting PSI monitors. Android17
init assigns minfree/adj root:system mode0664; lmkd runs in group system and has
current explicit SELinux write permission for sysfs_lowmemorykiller. Kernel
minfree/adj parameters and LMKD writes still exist. Failure to open the optional
kernel kill-event reporting file does not switch the selected killing mechanism
to a fabricated PSI interface. No new LMKD shim/property is justified by this
source review. Real sysfs labeling, threshold writes and low-memory behavior
still require device validation.

The actual boot sequence triggers load-bpf-programs before zygote-start. Nothing
in this review resolves the unavailable eBPF backend or its consumers. A real
alternate networking backend and truthful startup conditions remain required.
