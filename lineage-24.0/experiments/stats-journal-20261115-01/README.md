# Durable acceptance receipt and complete consumer-state journal

The inactive journal records real runtime kernel boot UUID, frozen bank/epoch,
a bounded opaque COMPLETE consumer state and SHA-256 integrity data. Exact
receipt/data replay is idempotent; conflicting or stale receipts fail. Unsigned64
epoch ordering survives the signed boundary. A prior-boot file remains untouched
until explicit new acceptance and never seeds this boot's counters. Corruption,
truncation and inaccessible storage are errors, distinct from definitive absence.

The actual FileStore uses AtomicFile, but does not trust its log-only failure
handling. It explicitly requires successful file-descriptor data sync before
finishWrite, verifies the parent descriptor is a directory, synchronizes the
directory and checks exact readback. Post-rename uncertainty leaves the base file
for explicit receipt-based recovery. No automatic write retry, ACK, SWAP, reset,
BPF flag or networking Ready is introduced. I/O requires the caller's existing
factory lock and takes no new Java system-service lock.

The runtime UUID reader opens the real proc path with CLOEXEC/NOFOLLOW, requires
a root-owned regular file and exact canonical UUID/newline input. This runs on
the device, never using a build-host UUID/property substitute. Existing current
platform proc_random rules permit the read; no SELinux source/input is changed.

Native02 compiles the actual journal and both clients against original current
Connectivity SDK classpaths, binds unchanged native prerequisites to11-RPC native
proof and passes1243/17 audits. Native01 exposed that O_DIRECTORY is not exported
by that SDK; the final source instead checks the opened parent's actual file type.
Host03 passes271 checks with real temporary data files/FD sync and explicit
Android Os/AtomicFile fixtures. This includes every-byte corruption/truncation,
forged headers, boot/unsigned epoch/replay checks,4MiB payload, uncertain writes,
rename/sync/close errors and runtime proc fixtures. Host01 had an ambiguous test
FileStore import; host02 injected its directory fault before the write instead of
after rename. Both fixture failures and corrected evidence are retained.

This is the durability primitive. Actual NetworkStatsFactory serializers,
poll/restore/ACK routing, interface history, counterset/UID lifecycle and consumer
state amendments still require integration. Restore must never undo UID cleanup;
that lifecycle needs explicit durable state transitions. No device power-loss,
actual Android IPC, ROM boot or flash readiness is established. Selected source,
prebuilts, strict policy inputs and signing/rollback material are unchanged.
