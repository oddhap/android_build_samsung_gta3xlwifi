# Actual coordinated full product build

Exit0:1,602 actual steps;19:15 total;1,243 projects/21 exact patches audited
before and after. This is the actual runner version used, including its harmless
literal backslash-n trailer bug in the two input metadata reports. Those exact
bytes are retained as inputs-before.raw.txt and inputs-after.raw.txt; the
geometry report binds their original digests. Source audits are valid JSON.
The current runner fixes formatting for subsequent jobs.

The target-files archive is saved privately on the build server, with digest
759386c11d8f71b2a0e65cec6819027e252ddc8c34df5bf5e90f8540357cbe4d.
Package geometry/policy identities,39-APEX actual-vendor VINTF metadata and the
four ext4 feature masks pass their respective checks. This is not an installable
OTA or Android17 FBE/runtime approval. Original Android14-only installer hooks
are still present in this historical product; the next source snapshot replaces
them with a strictly read-only, matching-header preflight.
