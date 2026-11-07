# Candidate seven-bit UID permission values

Mirrors actual A17 UidPermissionChunk bit identities: LocalNetwork0, UpdateStats1,
NoInternet2, UseLoopback3, ForceLoopback4, AcrossUsersFull5 and AcrossUsersOrProfiles6.
NoInternet is NEGATIVE; absent mask0 does not deny Internet. It is not the legacy
traffic-permission bitmap. Inputs reject negative framework UIDs, unknown bits
and ambiguous duplicate full-snapshot entries, preserving prior state on errors.
Snapshots/matching UID lists are sorted; zero entries are canonicalized away.

The pure loopback query implements actual uids_have_loopback_permissions, including
per-user core IDs, same profile, sender FULL, receiver FORCE+FULL, and same-appId
sender across-profile permission. Its inputs follow that UID predicate's contract:
packet code normalizes sender raw65534 separately; receiver creator65534 stays
literal. It performs no packet eligibility, peer lookup or live permission query.

46 structural/error/default/canonical cases and1048576 actual loopback predicate
comparisons plus1048576 actual migrated socket-create negative-bit comparisons
pass under fatal UBSan. All128 masks for each endpoint and eight UID views cover
all relevant/irrelevant bits. Actual A17 expressions/macros are extracted, with
permission-map fixtures. Whole socket-create fallback, kernel enforcement and
publishing are outside this value. Actual Android17 ARM64 netd CFI compilation
and relocatable-object architecture checks pass with complete1243/17 source audits.
No maps, callbacks, properties, active source or network readiness are changed.

The kernel still needs REAL dynamic NoInternet enforcement and a protected live
permission store before this value can be published. Static inet group checks
alone do not implement the selected A17 UID permission migration contract.
