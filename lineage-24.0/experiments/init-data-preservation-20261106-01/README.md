# Preserve userdata on init recovery-error paths

Active source integration in snapshot `port-20261106-02`. Scoped by the existing
`GTA3XLWIFI_LEGACY_FSCRYPT` build flag; all other products retain upstream behavior.

Actual Android17 `reboot_into_recovery()` now rejects recovery wipe options
before writing the bootloader message or triggering shutdown. Current callers
include mount failure, directory-policy failure and failed vold initialization.
The request returns an error. It does not report a successful mount/unlock,
change encryption policy, allow formatting, or modify SELinux. Ordinary recovery
requests without wipe options retain their original behavior. The test-device
userdata fstab already lacks `formattable`.

The exact function and `queue_fs_event()` bodies pass 50 cases for each product
profile (100 total) on both macOS and Linux, with fatal UBSan and empty stderr.
Synthetic effects cover BCB-write failures, Microdroid/GSI, all mount-event codes,
wipe flags in a later argument, nonwipe requests and side-effect ordering. There
are no actual BCB writes, storage, encryption operations or reboot requests.

Capture01 failed because its private Git index omitted the previously reviewed
new keyutils files; no build was started. Capture02 reversed only the hash-bound
guard, passed the complete parent audit, reapplied it, explicitly included those
reviewed new files and recovered the exact parent patch by reversing the guard
in the private index. All 1,243 revisions remain identical; only system/core's
reviewed patch changes. The full new-snapshot audit passes (16 exact patches).

`init-data-preservation-native-20261106-01` completed exit 0 with full before/
after source audits. The actual installed ARM64 init contains the new guard.
Native fscrypt verification was repeated after rebuilding: actual init/vold and
both keyutils architecture variants pass; the four previously tested fscrypt
runtime bodies remain byte-identical to host07. See the adjacent native/host
job reports and `fscrypt-native-evidence-20261106-02/report.json`.

This guard prevents these init-generated recovery wipe requests. It is not a
claim that every component or a manually invoked recovery is unable to erase
userdata. Native unlock, TEE, recovery compatibility and rollback remain untested.
The ROM remains unfinished and is not flash-ready. No device was accessed.
