# Isolated inode notification mediation

The preserved profile enables both INOTIFY_USER and DNOTIFY. This candidate adds
the real LSM path_notify API, initialized head, hook registration and SELinux
inode watch/watch_reads permission checks for both paths. The hook is independent
of CONFIG_SECURITY_PATH, as in the modern kernel. No assertion or enforcement
setting is changed. Existing read/DAC checks and event conversion remain intact.

The Samsung inotify path is canonicalized for stacked filesystems before mark
insertion. Authorization therefore checks the actual canonical mark target,
then inserts a mark only on success. Path/fd release is preserved on denial.
Dnotify checks the converted event mask before its first allocation; removal of
an existing watch retains its original fast path without new authorization.
The old file-inode initialization and d_backing_inode implementation were read
before choosing the path hook: both identify the mark's inode in this profile.

Only inode marks are supported here. Non-inode marks and permission-event masks
return EOPNOTSUPP. Enabling FANOTIFY deliberately fails compilation until its
mount/superblock/permission mediation exists. No unsupported feature is claimed.
The common file prefix gains watch/watch_reads: existing class numbers and
relative permission-name order stay intact, but file-specific bit positions
move. A complete kernel/header rebuild and export review are required.

Mac ASan/UBSan actual-body fixtures pass 2,359,296 inode permission scenarios,
2,304 complete inotify syscall/canonical-path/refcount scenarios and 3,072 dnotify
authorization-prefix scenarios. Actual inode/path helpers, SELinux and vendor
LSM dispatch, initialized/registered hook list and full inotify syscall run with
fixture objects/backends. Dnotify stops before its first allocation, so its full
mark lifecycle is not covered. Event definitions come from locked target headers.
The FANOTIFY-enabled compilation control rejects the intended unsupported mode.

The initial stager stopped safely on an absent include anchor; its partial tree
is preserved and unused. The new candidate uses the actual file.h anchor. This
was a staging match failure, not a failed enforcement test hidden by source edits.
No active Android source/prebuilt, tablet partition or signing key is changed.
Netlink capability9 rejection, perf, strict policy, networking and installer/FBE
remain separate installation gates.


## Complete standalone build and Linux fixtures

`kernel-notify-build-20261104-01` completed exit0 at 18:35:33 UTC on November 4,
followed by `kernel-notify-host-20261104-01` exit0. Mac/Linux result, input and
runner hashes match. Image SHA256:
`ad12b0401809b8aad02e7e905a5753eb73d825b03c3e6a10e58357a27320ee3f`.
The complete 60,331-file tracked-source/protected-input audits pass. Preserved
config, firmware and all original 8,408 export symbols/CRCs match. All three
untracked source files are identified and hashed. Source inventories remain on
the server and are bound by evidence-lock.json. Dnotify's real early-error cleanup
was also read: the pre-allocation denial path sees both cleanup pointers NULL.
No Image promotion, live watch/mark lifecycle or flash approval follows.
