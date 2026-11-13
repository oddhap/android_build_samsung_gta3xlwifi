# Exact socket DNS context and private ingress predicates

Extends the exact-skb UID snapshot with genuine system-DNS/direction metadata
copied from the same real qtaguid query in the actual socket hooks. Nested
synchronous evaluations restore the whole context. Compatibility UID-only APIs
supply false rather than invent a DNS identity. Context73/864 and actual socket
hook92(+prior51/100/1797 and5632/98304 comparisons) tests pass.

Two read-only, private-table-scoped matches are registered together:
- bad_iif: mismatching numeric allowed interface, with true DNS/lo/output exemptions.
  Allowed0 means lockdown DROP on all non-DNS/non-lo input. Explicit IIF-present0
  wildcard must produce NO drop rule and suppress lockdown.
- ingress_discard: exact IPv4-mapped/IPv6 destination and two allowed interfaces;
  DNS does not exempt it. Uses the actual existing relative-L3 parser, including
  valid destination with unsuccessful L4 parsing. No fake kernel version switch.

Checkentry rejects other tables/namespaces, unknown families, reserved data,
indices above INT_MAX and unassigned zero/mapped-zero destinations. Info layouts
are8/28 bytes. Actual registration bit512 contributes to the feature query only
alongside genuinely registered dual-stack private tables (bit256). No ioctl,
SELinux grant/assertion, global NF hook, automatic rules or readiness changes.
The future compiler must place these AFTER ordinary rules within existing
system/owner-skip exemptions, with discard BEFORE IIF. Native state/compiler and
complete transaction/startup integration are not supplied by this kernel stage.

32 assertions plus240 actual A17 owner and2160 actual A17 discard comparisons pass.
Parsing/metadata/registration effects are fixtures in that oracle harness; actual
parser and exact context are separately tested. Historical host01 had fixture
prototype/type errors;02 passed C assertions but an incorrect expected-count guard;
03 fully passes. All attempts are retained.

Full kernel/modules exit0 at03:37:06UTC November13:
Image01e95fbb438b2fddf6464df8ced38e5027eb8a94e5d99803fd9361d0de30af59;
configfac42 unchanged,60357/60331 files and1243 projects/17 patches before/after,
Gator118/KUTF43 version imports pass. Actual ARM64 call relocations target the
metadata-aware helper. No selected Android image/policy changes or hardware test.
