# Isolated vendor namespace separation and capability narrowing

This metadata candidate reuses the checksum-bound private UWB alpha-rename and
removes exactly one old vendor allow: system_server_30_0 to itself for capability
sys_module. Android17 explicitly forbids that capability for system_server. No
neverallow/neverallowx declaration is deleted, disabled or relaxed; private type
identifiers are renamed consistently. Inverse renaming reproduces the original
CIL byte-for-byte except for the one removed allow. Allow count is 12,528 to
12,527; 131 neverallow and two neverallowx assertions remain.

The Samsung endpoint `vendor.samsung.hardware.uwb@1.0::ISehUwb/default` is preserved
and is distinct from the platform `uwb` and `android.hardware.uwb.IUwb/default`
endpoints. Only its context type changes. The platform/vendor type namespacing
rationale follows [AOSP policy compatibility guidance](https://source.android.com/docs/security/features/selinux/compatibility).
Actual endpoint/context source hashes are recorded; providers, clients and
runtime permissions are not validated by this metadata-only check.

Strict actual Android17 production-policy compilation still **fails**, with 319
diagnostic blocks versus 322. Exactly the two namespace collisions and the
system_server module-capability conflict disappear; no diagnostic assertion is
new. The comparison JSON's historical `removed_constraints` field denotes
resolved compiler diagnostic records, not deleted policy assertions. Source
assertions remain present. Only vendor_sepolicy.cil changes among ordered compiler
inputs; every other input and the compiler hash are identical to the baseline.
No assertion-disabling compile is run in this experiment. Full 1,243-project,
15-patch before/after source audits match (excluding generated timestamps).

`metadata/report.json` on the server describes the intermediate namespace-only
stage. Its hash is retained in tightening-report.json; the latter describes the
final narrowed policy and counts. The parent report is not final-image approval.
The patch is relative to extracted etc/selinux, not a binary image. It is not in
active snapshots. Original MTP-fixed vendor, precompiled policy/cache hashes,
firmware, signing material, kernel, recovery and tablet data stay untouched.
No vendor image or installation candidate is produced. Effective-policy, label,
cache-invalidation and runtime review remain necessary before integration.
