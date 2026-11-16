# Zygote cgroup source review

Reviewed against selected snapshot port-20261116-01. No source was modified.
The companion manifest binds the exact reviewed files.

- `com_android_internal_os_Zygote.cpp:1986` calls `createProcessGroup(uid, getpid())`.
- `system/zygote/zygote/src/species/android_native.rs:301` calls `cgroup::create`;
  its implementation invokes `createProcessGroup(uid, pid, false)`.
- `system/zygote/zygote/src/server.rs:910` actually invokes `sys::fork()`.
  Adjacent clone3 error comments describe a planned upstream change, not the
  syscall currently executed.
- The Rust `create_for_clone_into` wrapper and C++ `createCGroupForCloneInto`
  still report an error on this device. Neither reviewed zygote route calls
  that wrapper. No successful clone3/cgroup-v2 support is claimed.

This closes the specific uncertainty about these callers requiring clone3.
It does not validate cgroup mounting, profile application, process cleanup,
Android boot or physical device behavior. Re-review if these sources change.
