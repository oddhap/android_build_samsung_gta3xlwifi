# Frozen Android11 classification reference

Official Android17 build modules `30.0_plat_policy.cil` and `30.0_plat_policy`
compile the locked frozen API30 public/private sources in their explicit user
variant. Build exit0, 7m33s including graph regeneration, followed by matching
full 1,243-project/15-patch source audits. Modules are not installable. Original
Image/DTBO/MTP-vendor input hashes remain exact. No snapshot or image is changed.

This is an Android11 app-classification reference, **not Android17 ROM or security
validation**. The CIL SHA-256 is
`94007d1d20ce24a4f2a74920d82f0fabc2a0718cb61bb5996b7fa7dad64d67e9`;
the binary SHA-256 is
`549d8d4306fede627d02e27e07d336488c1c6c7378fe0defeb4773087a31e8a9`.
The report records exact source/output hashes and audit bindings. The downstream
ASEC proposal records the actual appdomain member list it reads from this CIL.
