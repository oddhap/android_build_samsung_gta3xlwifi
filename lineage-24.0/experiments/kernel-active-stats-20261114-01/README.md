# Non-consuming active packet-statistics snapshot

Adds kind3 to the existing versioned READ payload, with the same ioctl number,
size and layout. Requires the exact nonzero current active epoch. Selection,
rows, counts, loss and sequence are captured under the real stats lock. Copyout
and sorting operate on that immutable snapshot. No swap, ACK, clear, pending-bit
change or estimated counter is introduced. Private bit15 advertises this compiled
reader; it is not a SELinux policycap or whole-network readiness assertion.

All source outside stats_read and stats_features is identical to the fully built
runtime prerequisite. The complete prior storage/GSO/concurrency fixture runs on
the current module bodies, with only the new documented kind/capability expected.
It passes 5,396 cases, 9,830,400 A17 GSO comparisons, the prior 80,000 concurrent
updates and another 80,000 updates while reading the active bank. Tests include
all four INET/IPv6 feature configurations, stale/empty/full/loss snapshots and
copy/allocation errors without lifecycle changes. Earlier fixture failures are
retained. Unrelated strict source-identity replays explicitly use frozen inputs;
they are not represented as execution of the changed reader.

The complete Image/modules build, Gator118/KUTF43 import checks, unchanged product
configuration and full candidate/protected/Android source audits pass in
kernel-active-stats-build-20261114-01. No image, policy, original source/output,
firmware, vendor input or tablet is changed. Existing SELinux READ permission and
all previous ioctl boundaries remain; no extra grant or assertion change is used.
