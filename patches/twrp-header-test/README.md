# Diagnostic-only recovery header test

This patch is NOT part of the production source-project patch list and must
not be applied to a normal Android or recovery build. It was used only for
the controlled header comparison documented in ../../docs/twrp-header-compat-test.md.
It is a diff for the TWRP 12.1 system/security project, preserving upstream
per-file licensing.

When recovery Keystore2 receives environment variable
TWRP_HEADER_TEST_READ_ONLY_KEYS=1, its legacy KeyMint adapter rejects key
generation, import, wrapped import, upgrade, delete and delete-all before
calling the hardware HAL. Existing-key read/use operations remain available.
The temporary init overlay supplied that environment variable. The temporary
startup script allowed only Android 14 / ROM SPL 2026-09-01 with a header month
of August or September 2026, and preserved those live ROM properties in both
images. The images differed in only header byte 44.

The patch and diagnostic init changes were removed after the test. The normal
library rebuilt byte-for-byte, and the published production recovery was
restored and verified. No raw logs, keys or personal data are included here.
