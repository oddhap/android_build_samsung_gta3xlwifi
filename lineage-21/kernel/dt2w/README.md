# DT2W kernel source and build inputs

The candidate Image was built from the published kernel base
`efbdbfa3e216b0c300d381c340b0a22b24e15c13` with the included four-file patch
applied as a working-tree change. Its version string therefore retains that
base revision and the dirty suffix. The corresponding code changes have also
been committed for review; `notes/source-inputs.lock.json` records that commit.

For the original build setup, create a clean kernel checkout at that base,
apply `kernel-double-tap-wake.patch`, and run `bash build-kernel.sh` from this
directory. Set `KERNEL_SRC`, `KERNEL_OUT` and `KERNEL_ARTIFACTS` when using other
paths. The output directory must be separate from the source checkout.
The recipe uses the checked-in complete kernel configuration, copies the
upstream UH/ACPM inputs required by the vendor makefiles, and retains the
original Android R kernel flags. Use the original GCC 4.9 toolchain at revision
`961622e926a1b21382dba4dd9fe0e5fb3ee5ab7c`.

The build timestamp, counter (2), user and host in the recipe match the candidate. Reusing
an output directory or building directly from the later committed kernel can
change build counters/version metadata and therefore the resulting checksum.
No signing keys or proprietary Android vendor extraction are part of this
kernel recipe.

Candidate Image SHA-256:
`33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553`.
Config SHA-256:
`fac42e3bbf996bb9502bb1031c91b1950986ad3586d0f33cad869a6fd0b3acea`.
The candidate retains the preceding Kconfig settings and DTBO. Actual
double-tap wake behavior still requires physical validation of the matching
Android device/native integration.
