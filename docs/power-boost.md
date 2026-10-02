# SM-T510 bounded power boost

Implemented and installed, 2026-10-02. This is part of the native LineageOS 19.1
build, not a GSI and not a claim of production stability.

The PowerManagerService JNI layer forwards interaction and launch hints to a
product-selected native backend. The original Samsung AIDL/HIDL services remain
in place. Only this product enables the Soong `native_power` option.

- Touch defaults to 400 ms, with explicitly requested durations bounded to 2 s.
  CPU floors: little 1248 MHz, big 1352 MHz. GPU minimum: 545 MHz.
- Launch lasts until Android ends the launch hint, with a 2 s fallback.
  CPU floors: little 1248 MHz, big 1560 MHz. GPU minimum: 676 MHz.
- Screen-off and battery saver clear both requests synchronously. Wake or leaving
  battery saver does not restore an expired request.
- The steady-clock worker releases floors even if no further hints arrive.
- CPU requests have independent kernel file-descriptor lifetimes. Closing the
  descriptor or system_server exiting releases only this backend's CPU request.
- Two kernel misc endpoints (`gta3xlwifi_cluster[01]_min`) share the existing CPU
  QoS classes and ABI; original vendor endpoints and their labels are unchanged.
- GPU minimum uses a separate FRAMEWORK_LOCK slot in the existing driver.
  The `gta3xlwifi_min_lock` sysfs endpoint controls only that slot. Zero releases it;
  zygote restarting/stopped init triggers also release it after process failure.
- CPU/GPU maximums, thermal controls, and governor configuration are unchanged.
- Control-open/write failure disables the backend rather than crashing
  system_server. Diagnostic transition logging is opt-in through
  `debug.gta3xlwifi.power_log`, and must be off after testing.

Samsung miscpower opens the touch `enabled` and battery `lcd` nodes as UID/GID
system. Existing vendor SELinux policy already allows these nodes; the fix sets
0660 system:system ownership in `system_ext/etc/init/init.gta3xlwifi.power.rc`.
The legacy ramdisk destination is unused by this system-as-root build, so the
power init file is copied into the automatically loaded system_ext init directory. A live test after restarting the
service confirmed both file descriptors opened with SELinux Enforcing.

Sources: `device/samsung/gta3xlwifi/power`, framework patch
`patches/lineage-19.1/power-boost.patch`, kernel patch
`patches/kernel/framework-cpu-qos.patch` and
`patches/kernel/framework-gpu-floor.patch`. Framework revision:
5f6b8d6098f8d858d1450db45c350c7ba08ae455; kernel revision:
00e4b9481434f9b0b644925a9bb2feaf3940219d. Existing networking, camera and SystemUI
lifetime fixes must remain applied.

Six BoostWindow tests passed on both host architectures. Framework native
module and platform SELinux checks passed for the initial backend. A GPU
endpoint label collision with stock vendor policy was caught before packaging;
the independent GPU endpoint resolves that collision. Final combined policy, full ROM build, image and package checks passed. The
verified package was installed without formatting data (TWRP updater RC 0,
117 seconds). Boot and TWRP partition readback hashes matched their expected
images; TWRP was preserved.

Packaging guards caught two integration issues before flashing: the power init
file needed a system_ext destination because the legacy ramdisk is unused, and
the custom boot rule omitted an explicit kernel dependency. The build rule now
depends on the installed and prebuilt kernel, and the independent image verifier
requires the new source-built kernel SHA-256 in both boot and native recovery.

Runtime touch boost reached CPU QoS aggregates 1248000/1352000 kHz and GPU
545000 kHz. The aggregate CPU baselines are the driver's hardware minimums,
449000/936000 kHz; releasing our request restores those values rather than zero.
Launch logs show GPU 676000 kHz and big CPU 1560000 kHz. Expiry, screen-off,
wake, and battery saver tests passed with SELinux Enforcing. Battery saver tests
used temporary BatteryService unplug/level overrides because USB charging would
otherwise prevent enabling saver; real battery state and saver/logging settings
were restored afterwards.

The same short launcher drawer test measured 745 frames / 374 janky (50.20%)
before and 794 frames / 169 janky (21.28%) after. Median frame time: 26 to 19 ms;
95th percentile: 53 to 36 ms. After-test AP temperature 31.0 C, battery 27.3 C,
thermal status 0. This is one synthetic before/after run, not a guarantee for
all apps. Long-term battery consumption and production stability remain untested.

There are unrelated pre-existing vendor/property/cgroup denials; these changes
address the two miscpower control access failures and the bounded boost backend.
No new boost endpoint access denials or backend write failures were observed.

Crash cleanup passed: a diagnostic CPU request reached 1248000 kHz and returned
to 449000 kHz when its fd closed. A diagnostic GPU floor was cleared by init
before the replacement system_server started (3716 -> 6981). Exactly one
intentional framework restart was performed; battery overrides were reset.
The deployed ZIP is `lineage-19.1-20261002-UNOFFICIAL-gta3xlwifi-power-boost.zip`,
SHA-256 58e338e00fed0fbb9a96d2bce46c289322cf8ecc0aaea7845f2c0d74f8611c40.
