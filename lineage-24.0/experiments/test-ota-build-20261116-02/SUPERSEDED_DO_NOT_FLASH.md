# Invalidated by physical startup failure

Do not install OTA aa681b3199d1072948e6cc9c835019513c34c96545fd414639dc4366fe4cbc58.
Its static helper aborts in Bionic before its real preflight on Linux4.4 because
MADV_WIPEONFORK is unsupported. These retained package proofs describe the old
artifact and do not supersede this actual runtime failure. A whole replacement
ROM/OTA must include the snapshot04 libc fix; replacing only the ZIP helper is
insufficient. See the arc4random source/build/physical-startup experiments.
