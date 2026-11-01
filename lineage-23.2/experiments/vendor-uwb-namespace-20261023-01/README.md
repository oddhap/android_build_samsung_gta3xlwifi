# Samsung private UWB type namespace — isolated metadata experiment

**NOT a vendor image, ROM, installer or security approval. Not applied to TOP.**
This is an extracted-filesystem metadata patch, **not an apply-port snapshot or a
Git project patch**. Do not replay it against a prebuilt image or preserved source.
Use the checksum-bound staging tool to reproduce it in a fresh outside-TOP scratch.

## Concrete collision and scoped fix

Samsung's Android-11 vendor CIL defines private `uwb_service` and `hal_uwb_service`.
Android 16 defines platform types with those same names. Init's multi-declaration
link merges the types/attributes/permissions. In particular Samsung grants
`platform_app` add/find on its UWB type, but the merged Android-16 type is a
`system_server_service`. This violates both old vendor and modern platform
neverallows; it also assigns unintended framework registration TE permission.

The proposed metadata delta alpha-renames **only vendor-private** symbols to:

- `vendor_samsung_legacy_uwb_service`
- `vendor_samsung_legacy_hal_uwb_service`

Only **two files change**: `etc/selinux/vendor_sepolicy.cil` (symbol tokens, not
comments/strings/substrings) and `etc/selinux/vendor_service_contexts` (one context
field). The endpoint name remains
`vendor.samsung.hardware.uwb@1.0::ISehUwb/default`; only its private SELinux type
changes. Modern platform and versioned public CIL are untouched. No allow,
neverallow, permissive statement, class or service name is removed or added.

`metadata-lock.json` records all nine copied text inputs and before/after hashes.
Byte-exact inverse rename and actual Git forward/reverse replay restore **all
original metadata**. No source/image is overwritten. The scratch is deliberately
**not a complete vendor tree**: compiled policy/hash caches, binaries, `sk`,
certificates and other files are not copied/read by the tool. ODM policy, public
symbol overlap, unknown context references, checksum/version mismatch, aliases,
nonregular inputs and existing/protected outputs are rejected. A real image
integration must review labels/cache invalidation/provenance separately.

## Real compilation and TE inspection

Actual production `user` platform inputs plus the proposed vendor CIL:

- Strict secilc **255**, checker **1**: **279 diagnostics**, versus original 281.
- Precisely two diagnostic identities disappear:
  `vendor_sepolicy.cil:11914` and `system/sepolicy/private/system_server.te:1043`.
- **No new diagnostic identities**. Every other ordered policy input/hash is
  identical; no optional input is dropped. The final-tool scratch (-04) is
  byte-identical to the metadata compiled in -01.
- Init-style `-N` binary linkage works **only diagnostically**, not approval.
- A host inspector linked against actual source-locked Android libsepol checks
  **505 concrete domains × 4 target types = 2,020 queries per policy** for
  unconditional `service_manager` add/find TE rules. **No newly granted add/find
  pairs** in any of the four before/after type comparisons.
- `platform_app` can no longer add Android-16 `uwb_service`, but retains its old
  Samsung add permission on the separate legacy type. `system_server` still has
  framework registration permission. Modern `hal_uwb_service` pairs are unchanged.

**Important functional limit:** Legacy UWB targets lose 28 and 4 merged-policy
add/find pairs respectively. These include inherited modern framework clients and
AOSP `hal_uwb_default`; their loss is not an automatic runtime approval. The vendor
rule graph is preserved by renaming, **not all accidental merged permissions**.
Actual callers, hardcoded context strings, feature availability and HAL behavior
need review before image integration. Conditional rules/constraints/MLS, live
kernel enforcement and endpoint availability are not evaluated by the TE inspector.

## Tests, source status and paths

**18 regression/safety tests PASS on Mac and Linux**. Tests are synthetic metadata
fixtures, not real SELinux execution. Actual original-input compilation, real
libsepol binary queries and Git replay are separate evidence above.

`tools/stage-vendor-uwb-namespace.py --top TOP --vendor ORIGINAL_EXTRACTED_VENDOR
--output FRESH_SCRATCH --expected-policy-sha256
8df663eb65a807e6ee99f8b2384cb52d34c994a25087410486b1f88e278e2e53`
(all arguments on one command line). The input vendor must be the original
checksum-verified extraction, not this metadata-only scratch.

Remote artifacts under `/srv/android/artifacts/lineage-23.2-arm64/`:
`vendor-uwb-namespace-20261023-04/`, `vendor-uwb-policy-20261023-01/`,
`vendor-uwb-analysis-20261023-02/`; earlier attempts retained. Compile input -01 and
final staging -04 have identical bytes. Full evidence:
`reports/vendor-uwb-namespace-20261023.json`.

Source audit still **1,168 projects / 13 patches / snapshot 06**, no promotion.
The original production policy still fails 281; archived complete userdebug images
still fail 367. The proposed metadata still fails 279 — **not a security pass**.
Full Netd/packet backend, remaining policy/capability/runtime/HAL/APEX/FBE/recovery/
OTA/signing/owner-approved backup/rollback/hardware validation are still required.
Original vendor/Image/DTBO, LineageOS 21, TWRP, keys and userdata are untouched.
