# XDA follow-up — 12 November 2026

Scope: LineageOS 21 ARM64 for SM-T510 / gta3xlwifi.

- A user reports successful Xubuntu GIO/GVfs MTP integration tests with
  independent ADB/SHA-256 checks on the November 1 release. This is external
  confirmation; the suite has not been independently reviewed here.
- The reported disabled USB Settings menu was not reproduced on the test
  SM-T510. The November 1 build reports a connected USB port in device/sink
  mode; selecting File transfer and No data transfer in Settings changes the
  active functions to mtp,adb and adb respectively. The port is also connected
  after recovery/Android return. No USB Port HAL fix is claimed. Further
  diagnosis needs the affected device's USB dump, cable/host configuration
  and logs from the disabled-menu state.
- Minimum-brightness failure is confirmed. Logical float brightness 0 sends
  panel level 1, and both HX8279D panel lookup tables map level 1 to zero PWM.
  Android's simple brightness mapping ignores the configured positive
  backlight minimum when nits calibration is absent. The source fix maps
  logical [0,1] to the configured backlight range and provides the inverse
  mapping. It introduces no invented nits calibration. The screen-off sentinel
  continues to bypass this mapping in LocalDisplayAdapter.
- The actual mapping method and Android Spline compile on the host JVM. Tests
  cover endpoints, monotonicity, bounds, inverse and default identity at 1001
  points each for three minima. Baseline fails and the source fix passes.
  The new mapping has not yet been installed or runtime-tested in Android.
- A physical temporary-PIN test on the November 1 ROM and supplied ARM64 TWRP
  passes: set PIN, lock/unlock, recovery decryption by owner-entered PIN,
  encrypted storage read/write, unchanged 13 key-file hashes in recovery,
  Android reboot/unlock and removal of the temporary PIN. A marker created
  before setting PIN remains intact throughout. This does not reproduce the
  reported corruption or establish the affected user's cause. No formatting
  was performed; recovery is unchanged and test markers are removed.
- SM-T515 is unsupported. A T515 bootloop does not establish an SM-T510
  regression; the LTE model requires separate device/vendor/modem support.

Latest official LineageOS 21 refs were fetched on 12 November: 281 projects,
22 advanced. All 1430 pinned source HEADs and local changes were preserved
before updating; the existing port patches are re-exported on their new bases.
Only ARM64 LineageOS 21 is updated. No new ROM release has been built, installed
or published in this follow-up, and no XDA messages have been posted.
