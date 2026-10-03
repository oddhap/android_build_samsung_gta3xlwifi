# LineageOS 21 source upload

Private branches `lineage-21.0` are present in the existing device, kernel, vendor
and integration repositories under oddhap. Remote branch heads match the local
commits in `github-repositories.json`. The Android 12 and TWRP branches remain
unchanged. The kernel and vendor source trees have no new changes in the port.

The integration branch contains all ten complete platform patches, source
manifest and locks, reviewed legacy network core, tests, staging/build tools
and offline verification tools. Large images, test executables, SSH credentials,
GitHub tokens and raw device logs are excluded. The full ROM build and offline
image/layout/ZIP/VINTF/runtime-policy checks pass. Candidate 6 boots Android 14 with enforcing SELinux and encrypted file data;
Bluetooth, IPv4/DNS, process-group lifecycle and bounded power tests pass.
Complete physical hardware testing is in progress; the branch remains a development port.

GPU memory reads in libmeminfo also require a kernel capability guard. Under
image-app load, AppProfiler.reportMemUsage calls Debug.getGpuTotalUsageKb and
the unsupported BPF map constructor aborts system_server. Both per-process
and aggregate GPU readers return unavailable when the kernel capability is
false; Debug already represents this as -1. No fake memory total or accounting
subtraction is introduced. An optional noninstalled probe exercises all three
GPU APIs and ordinary RAM accounting. Full candidate 7 tests are pending.
