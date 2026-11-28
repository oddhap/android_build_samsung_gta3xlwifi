# sdfat `exfat` alias (LineageOS 21 kernel, 27 November 2026)

vold mounts exFAT cards only if `/proc/filesystems` lists `exfat`. Samsung's
sdfat driver implements exFAT but registers only `sdfat`. The one-file patch
`sdfat-exfat-alias.patch` (same as the LineageOS 24 build-53 patch) registers a
second `file_system_type` named `exfat` with the same mount and teardown paths,
as later sdfat releases do with `CONFIG_SDFAT_USE_FOR_EXFAT`. No Kconfig change.

Build: start from the DT2W kernel inputs in `../dt2w` (base
`efbdbfa3e216b0c300d381c340b0a22b24e15c13` plus `kernel-double-tap-wake.patch`),
apply `sdfat-exfat-alias.patch`, and build as described there.
`build-kernel-exfat21.sh` is the exact script used: it first proves that its
copy reproduces the released DT2W Image `33c1a0d1…` byte for byte (after
substituting the build path, except the GNU build-id), then applies only this
patch and runs `test-kernel-sdfat-exfat24.py` (10 host cases).

- Patch SHA-256: `e3ffcd8e7f35cf9279898ec1e845c01c946e221d7276ae4b12a09627ae24e0cf`
- Image SHA-256: `c7b4a44fcb4f31ea53d86fe000270d6a20d0f9d3e5a84ae9249c9d0acba19aca`
- Configuration identical to the DT2W kernel; exported symbol CRCs unchanged;
  release string `4.4.302-gefbdbfa3-dirty` kept.

Not yet physically tested on LineageOS 21.
