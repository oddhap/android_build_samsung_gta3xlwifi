# Reject silently filtered qtaguid accounting

The actual Samsung kernel zero-initializes procfs owners and filters detailed
rows by the statistics file's group. Android17's system-server group list retains
3006/3007, but the carried init configuration did not assign them to qtaguid. A
readable table could therefore silently contain only UID1000 counters.

Device commit87313db adds only four metadata commands during `on init`: root /
net_bw_stats with0440 for statistics, root / net_bw_acct with0660 for control.
Existing startup/shutdown hooks remain unchanged. No kernel UID limiter is
disabled. The real Android init verifier accepts the script. Actual compiled
production/debug policy queries permit metadata setup and statistics access,
including the filesystem getattr needed by fstatfs; no SELinux grant was added.

The native reader checks a real regular procfs file. Detailed accounting requires
root-owned/statistics-group-owned input plus effective/supplementary statistics
group membership. Unknown ownership, filesystem or group failures return errors
and preserve caller values. This private system-server reader deliberately also
rejects unqualified root callers; interface aggregate tables do not use UID row
filtering. The known privileged group makes the actual kernel membership
predicate permit all UID rows, independently of the current filesystem UID.

37 Linux fatal-UBSan cases pass using the full reader/parser and the exact kernel
permission predicate, with synthetic metadata/FILE effects. They reproduce the
old gid0 filtering problem and cover credentials, ownership, inode/filesystem,
getgroups errors/races/bounds, existing parser/aggregate cases and unchanged error
outputs. No real counters or user data are accessed.

The complete isolated ARM64 CFI/APEX31 module links successfully, retaining its
exports and dependencies. The first retry exposed a build-wrapper duplicate:
integrated Soong response files already contain the two helper objects. The tool
now substitutes existing objects or adds absent ones, exactly once; it does not
suppress multiple-definition or undefined-symbol checks.

Current snapshot port-20261106-04 audits 1,243 projects and17 exact patches. Only
Connectivity's patch and the device revision e998→873 change from snapshot03.
Private-index reversal recovers the exact parent patch. The actual project
build completed exit0 in4m45 with full before/after audits. The actual ARM64
expanded-APEX library, ARM32 static archive and installed product init script
pass the source/test-identity check, using the37-case report. Original kernel,
MTP vendor and DTBO hashes are unchanged. The Java source is unchanged from01.

This is source, compilation and synthetic-effects evidence. Runtime credentials,
procfs behavior, counters, complete networking, packaging and hardware remain
untested. The ROM is not flash-ready; no policy-image selection or device access
occurs here.
