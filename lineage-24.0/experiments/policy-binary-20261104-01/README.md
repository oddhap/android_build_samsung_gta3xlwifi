# Actual Android 17 diagnostic binary and kernel reader records

The strict production/actual-MTP-vendor checker remains **failed** (322 diagnostic
blocks). Its expected exit 1 is saved separately. A second init-style `-N`
compilation is diagnostic data only: it does not override the strict result or
provide an installation policy. No input policy, neverallow or device changes.
Before/after audits pass for 1,243 projects and 15 exact patches.

Inspection uses the actual Android17 libsepol static library and headers, pinned
by revision and SHA256 in evidence-lock.json. The small read-only inspector was
carried as source from the historical tools and rebuilt against these current
inputs; historical outputs are not used as Android17 validation. Initial host
GNU ld could not read Android's compressed debug sections. finish-inspection.sh
uses pinned platform Clang/LLD without stripping or changing the library. It also
compares audits excluding only their generated timestamps. The original failed
runner remains recorded rather than silently rerun over its outputs.

The actual diagnostic binary has version 30, 3,989 types, 108 classes, **1,342
ioctl-kind-1 and 95 nlmsg-kind-3 records**. Capabilities 0, 1, 2, 5, **9** and 12
are active. Unlike the old Android16 diagnostic, netlink_xperm is enabled.

Extracted actual original and candidate AVTAB reader functions are tested against
eight real binary nlmsg records, adjacent ioctl records, controls and truncated
inputs. The original reader reproduces incompatibility; the candidate passes
25 cases. Type/class tables and I/O are fixtures, not a running kernel or full
policydb load. The actual candidate capability helper still rejects bit 9, as
confirmed by its 8,192-combination fixture test and source callsite ordering.
Record parsing is therefore a limited success: **whole-policy load remains
blocked**, alongside strict vendor policy. No guard is removed, no Image is
promoted, and no boot/enforcement/hardware or installation approval is claimed.

An initial reader-check shell stopped after the record suites because the guard
runner had not been uploaded. Uploading the unchanged tool and running that
missing check completed reader-summary.json; no failed reader result was changed.
