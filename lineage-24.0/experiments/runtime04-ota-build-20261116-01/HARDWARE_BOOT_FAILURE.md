# Physical first boot failed

The OTA installed successfully (updater RC0) and boot/vendor/recovery readbacks
passed. After owner-authorized clean userdata formatting, the actual device
bootlooped. Persisted last_kmsg contains repeated PID1 deaths about1.8 seconds
after kernel startup. USB/ADB never returned. Existing TWRP remains operational.
The packaged ROOT/init points directly to dynamic second-stage init; current
Android17 main requires a stage argument. Current-platform static stage one is
being integrated as a device-only product/root-link fix in snapshot05.
Do not treat package validation or physical installation success as a working ROM.
Do not repeatedly boot or reinstall this snapshot04 package to diagnose the issue.
