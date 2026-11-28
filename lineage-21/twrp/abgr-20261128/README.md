# LineageOS 21 TWRP with corrected colours (28 November 2026)

`twrp-3.7.1_12-gta3xlwifi-arm64-20261128.img`
(`947d409b9ffb819ab9920f5e5d468ba156c236dfc3a645020c1825ad1f7c9649`, 40273936 bytes)
is the 15 October LineageOS 21 ARM64 TWRP
(`10c2c2ee77ee593ace840a12fb90145809e4521942b681bcee6e9c3b364370ed`) with exactly two
ramdisk files changed:

- `system/lib64/libminuitwrp.so` `14a17810…` → `24a239bf…`: built from the same
  `twrp-12.1-pinfree` tree with only `TARGET_RECOVERY_PIXEL_FORMAT := "ABGR_8888"`,
  which adds `-DRECOVERY_ABGR`. The decon framebuffer reports BGRA, but the panel
  shows red and blue swapped, so the theme accent `#0090CA` appeared amber. An
  unchanged-configuration rebuild in the same output directory reproduced
  `14a17810…` byte for byte. The same library is in the LineageOS 24 TWRP, where the
  blue accent was confirmed on the tablet.
- `ramdisk-files.sha256sum`: that library's line.

fstab (including `/product`), crypto scripts, kernel, recovery DTBO, board, command
line, OS/patch word `0x1c0001aa` and the `SEANDROIDENFORCE` trailer are unchanged.
Only `ramdisk_size`, `recovery_dtbo_offset` and the SHA-1 id are recomputed
(`prepare-twrp21-abgr.py`, `report.json`). The Odin AP tar has the same layout
with the unchanged `vbmeta.img`.

OTA identity (SHA-256 over the image with bytes 44..47 zeroed):
`45344fd27769764622738f99d938ff3cce0d186764c7c23ddc872de292468bf0`. It is added to
the device's `recovery-header-sync` helper from build `gta3xlwifi.arm64.20261128.090043`.
`test-twrp21-header-sync.py` (14 cases, `header-sync-test.log`) checks preflight, a
chain of future OTAs (2026-11, 2026-12, 2027-06; only bytes 44..47 change and the
image stays recognized), downgrade and non-Android-14 refusal, the previous TWRP, and
that an unrecognized image is kept unchanged without blocking installation.

Not yet physically tested on LineageOS 21.
