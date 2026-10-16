# Preparing a fresh ARM64 build

The scripts preserve the tested Linux layout under `/srv/android`; provide
those inputs before invoking the build wrapper. You need the standard
LineageOS 21 build dependencies plus repo, Git LFS, Python pyelftools, lz4,
e2fsprogs and Android sparse-image tools.

1. Clone this `lineage-21.0-arm64` branch into
   `/srv/android/ports/lineage-21-arm64`. The `lineage-21/notes/pinned-build-manifest.xml`
   pins all 1,430 platform projects. Run `bash lineage-21/tools/sync-pinned-platform.sh /srv/android/src/lineage-21.0-arm64`
   for a fresh sync, then run
   `lineage-21/tools/apply-pinned-patches.py --top /srv/android/src/lineage-21.0-arm64`.
   `sync-arm64.sh` uses the original ARM32 checkout as an optional local reference
   and is intended for the original build workstation.
2. Clone the published ARM64 device branch into the source tree's
   `device/samsung/gta3xlwifi`. Device/kernel/vendor revision and input hashes
   are in `lineage-21/notes/source-inputs.lock.json` and publication provenance.
3. Build the updated ROM kernel using the complete config, four-file patch and
   recipe in [lineage-21/kernel/dt2w](lineage-21/kernel/dt2w/README.md).
   The candidate Image hash is `33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553`.
   Stage it at `/srv/android/artifacts/kernel-dt2w/Image`, or pass
   `--kernel-image` to `stage-arm64-device.py`; the locked checksum is enforced.
   Retain the original DTBO and baseline inputs under
   `/srv/android/artifacts/lineage-21-arm64/baseline-inputs/`. The October 7
   release retains its original kernel `9827c8ac986f7497428ac27e9bc309ac8b62ee08fbb414e6d0c81653537ea4a2`.
   Do not substitute the separate TWRP kernel.
4. Obtain stock T510XXU5CWA1/T510OXM5CVG2 vendor inputs under `/srv/android/vendor-stock`
   using the existing stock-extraction tools. Download donor SM-A305GT ZTO
   A305GTVJU8CWE1 firmware, with exact archive/image hashes in
   `lineage-21/notes/arm64-firmware-lock.json`. Place its ZIP in
   `/srv/android/vendor-donor/a305gt/firmware/`, run `extract-donor.py`, and mount
   its vendor image read-only with `noload` at `/srv/android/vendor-donor/a305gt/vendor`.
5. Run `audit-donor.py` with the stock vendor, baseline ARM32 platform and donor
   mounts available. The selected files and expected bytes are preserved in
   `lineage-21/notes/arm64-donor-summary.json`. Put the resulting donor audit
   reports in `/srv/android/artifacts/lineage-21-arm64`, then run
   `sudo python3 build-hybrid-vendor.py`. It guards against existing output,
   checks hashes/labels and preserves all but the three reviewed stock text files.
6. Prepare stock VINTF/metadata with the existing native-device staging tool;
   `stage-arm64-device.py` stages the exact reviewed Image, DTBO and hybrid vendor
   and retains the stock metadata. Its original-workstation recipe uses the
   separately staged ARM32 device's `configs/stock` and `vendor-metadata.mk`;
   keep that input available. No proprietary donor files are silently inferred.
7. Run `configure-arm64-release.py`, build using `build-arm64-candidate.sh`, then
   follow BUILD_ARM64.md for target-files, signing and verification. Published
   private release keys are unavailable; create and maintain your own signing
   identity for independent builds. Do not expect those builds to upgrade the
   published signed ROM without a planned key migration.

The 2026-10-07 ROM ZIP is the exact physically tested package. Its header helper
is the original one-image implementation. The published device source includes
the independently built/tested follow-up helper that recognizes the updated
PIN-free TWRP as well. Future builds include that helper; the tested ROM itself
was not silently rebuilt or re-signed for publication.

## ARM64 GApps and recovery follow-up

The current source snapshot includes 25 clean-index-checked platform patches.
The app relocation patches in Android.bp are necessary for GApps capacity;
Make's product-module override alone does not relocate Soong apps. Companions
such as JNI and privileged permission allowlists must move with their apps.
See [GApps integration](docs/gapps-arm64-build.md) and run
`lineage-21/tools/verify-gapps-headroom.py` against unsigned and signed target-files.
The Google ZIP is supplied separately and must remain unmodified.

For recovery, use the published `twrp-12.1-arm64` device branch and its
[ARM64 instructions](https://github.com/oddhap/android_device_samsung_gta3xlwifi_twrp/blob/twrp-12.1-arm64/ARM64.md).
The existing pinned recovery platform/vold fixes remain required. Build the
pinned ARM32 recovery first to provide the source-built vendor crypto runtime,
then stage the 22 compatibility files with `tools/prepare-twrp-compat32.py` and
apply `tools/fix-twrp-arm64-relink.py`. Use separate ARM64 output and enforce the
16 MiB compressed ramdisk limit; do not prune crypto support to fit the image.
