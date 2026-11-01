# Snapshot 02: deterministic patch object IDs

Supersedes port-20261101 for the active source audit. All 13 projects retain
identical source hunks; full object IDs replace repository-dependent abbreviated
IDs. Exact byte comparisons and SHA-256 checks remain enforced. The current
full manifest pins the owner-selected MTP vendor device revision separately.
