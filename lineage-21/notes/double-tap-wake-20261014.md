# October 14 ARM64 beta: double tap to wake

Status: complete ROM build, signatures, all nine offline gates, actual Samsung
vendor runtime-policy linking and physical tablet checks pass. The signed
October 14 build was installed with data preserved. The owner confirmed
physical double-tap wake on October 15, and the event observer captured a real
KEY_WAKEUP without injecting a wake event. Both Mali graphics ABIs (120 frames
and pixel readback each), all 104 baseline HAL interfaces, Wi-Fi/HTTPS, audio
output, front/back camera and accelerometer checks pass. Setting changes while
asleep and normal touch resume pass. PIN-free TWRP at the new October security
metadata decrypts CE storage automatically, reads/writes the storage marker,
and returns to encrypted Android with the wake setting preserved.

The paired recovery asset retains the October 7 tested TWRP payload; only the
four compatibility header bytes change. Its installed prefix matches the
published image. PIN entry was tested with the unchanged payload in the prior
release; it was not repeated with October security metadata. USB-disconnected
deep suspend, long-term stability and advanced hardware functions remain outside
this test scope. See `../../reports/dt2w-20261014/validation-summary.json`.
The October 7 public beta and its assets remain unchanged.

All 280 Lineage projects in the official LineageOS 21.0 manifest were fetched
from GitHub on October 14. Twenty projects changed; their exact revisions are
recorded in `upstream-refresh-20261014.json` and `pinned-build-manifest.xml`.
Fixed AOSP revisions and the Android 14 / LineageOS 21.0 product were retained.
Platform security date is 2026-10-01, and Chromium WebView is 155.0.8059.39.
All 13 existing platform patches still pass their pinned application checks.

The installed FTS1BA90A controller detected physical double taps in its proper
low-power mode, but reported KEY_HOMEPAGE and did not wake Android. Android also
lacked the framework capability and native touch suspend/resume integration.
The release addresses these together:

- Kernel: use KEY_WAKEUP for actual double-tap gestures; expose a boolean
  `double_tap_to_wake` control that preserves other low-power flags and handles
  unsupported hardware, shutdown and I2C errors.
- Device: enable `config_supportDoubleTapWake`; connect INTERACTIVE and
  DOUBLE_TAP_TO_WAKE modes to the two boolean controls independently of CPU/GPU
  boost readiness. A setting change while asleep reopens/closes the controller.
  The new input_enabled alias shares the original input core locking and
  users/disabled state; the old endpoint retains its Samsung vendor label.
- SELinux/init: grant system_server access to the exact two boolean endpoints
  with system:system ownership and 0660. No factory-command access is added.
- Verification: host sequencing/failure-injection tests, existing boost tests,
  kernel config comparison, and checks of the actual signed framework resource,
  both native libraries, init permissions and compiled policy.

Kernel base: `efbdbfa3e216b0c300d381c340b0a22b24e15c13`.
Reviewed Image SHA-256:
`33c1a0d1b9e2696decd53fbedfc2231385b74464f4058a54b93ff06ff7c72553`.
Kconfig settings match the preceding kernel; DTBO and hybrid vendor are retained.
Build identity: `gta3xlwifi.arm64.20261014.175643`.

The previously signed OTA, signed target-files and source revisions have been
preserved for rollback. A fresh complete encrypted userdata/EFS backup has been captured and verified
before installation. PIN-free TWRP reads the post-factory-reset CE storage and
the private storage marker correctly. No userdata formatting is part of the OTA.
