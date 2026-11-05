# Retire forbidden non-init core property writes

The complete actual compiler diagnostic identifies 25 reviewed vendor allow
statements writing restricted vendor properties from non-init core sources.
The stager resolves every source through positive CIL memberships and proves that
all its concrete members are core, excluding init. This includes both platform_app
and platform_app_36 behind the API30 alias. The first attempt stopped safely on a
singleton guard; the corrected proof handles all members rather than assuming one.
Failed attempt tools/logs/audit remain in the server's immutable label01 artifact.

Exactly those 25 property_service set grants are removed. Attributes, init's
exception, non-core writer grants and read grants stay unchanged. Two private
vendor-declared sources, policyloader_app and vramdiskd, are classified as core in
the linked policy and are included; "vendor writers unchanged" in the archived
tool/log means non-core writer grants, not every vendor-provided binary. Runtime
feature behavior still needs testing. No vendor-public scope fallback is added.

Strict diagnostics **61 -> 58**, no new diagnostic assertion identities. All
**5,918 assertion/constraint records** remain, with no AV additions or permissive
declarations. Full before/after source audits match: 1,243 projects / 15 exact
patches. Only vendor CIL changes among compiler inputs; all other hashes and the
compiler are identical. Final verbose diagnostics record **58 conflicts / 204
matching grant records**, without truncation. Secilc255 is still strict failure;
runner0 is completed analysis, not security approval.

These changes remain isolated metadata. No active snapshot/source/image, original
MTP vendor, kernel, cache hash, signing material, recovery or tablet is modified.
Network/BPF, remaining SELinux conflicts, HAL/ABI and Android17 FBE/installer/
rollback remain gates. No flashable ROM is produced by this experiment.
