# Wi-Fi-only and legacy capability cleanup

The 2026-10-04 usage audit found no current-boot crash/ANR, but exposed
unnecessary modem polling and optional statistics/profile failures.

## Source changes

- Android's mobile-data capability was still true. Set voice, SMS and data
  capability false, physical SIM slots zero and telephony hardware empty.
  Context-aware TelephonyManager returns zero for this combination. Its
  context-free default manager, used by PhoneFactory at startup, assumed all
  capabilities true and still created PHONE0 on hardware. Read static framework
  capability resources for that context-free case before allocating a modem.
  Products with voice, SMS or data keep their existing modem-count behavior.
  Remove the stock shared-image IMS feature through a product unavailable-feature
  entry. TeleService also gates both application enabled and persistent flags on
  a new capability boolean (true by default). The device statically overlays it
  false. Zero-modem PhoneFactory otherwise reaches a null default phone in
  AutoDataSwitchController, and persistent applications can still be launched
  despite a per-user disabled setting. The compiled manifest prevents that
  cellular process on this Wi-Fi-only product after boot or a data reset.
- Stop cpboot-daemon in the init event, before class main. Init Stop marks an
  unstarted service disabled, preventing its automatic class start. The stock
  daemon repeatedly opened the absent /dev/umts_boot0. Its vendor definition,
  binary and security domain remain unchanged. An initial service override was
  rejected on hardware by the Treble subcontext boundary; that approach was
  removed, rather than weakening init's boundary check.
- Stop mobicore directly in the init shutdown event, before EFS unmount.
  Its Samsung SIGTERM handler attempted a thread self-join. Init's explicit
  stop uses SIGKILL for this service (gentle_kill is absent), bypassing that
  broken handler and closing its EFS descriptors. Normal service startup and
  operation are unchanged. Keeping it shutdown-critical was rejected because
  its open EFS files could stall unmount and force last-resort termination.
  Reboot testing must check for both new tombstones and unmount timeouts.
- Release builds now generate and record a distinct timestamp/build number.
  Partial builds reuse that identity. The earlier release wrapper retained its
  first timestamp and default engineering incremental value across candidates.
  A changed TeleService APK then reused its old parser cache (PERSISTENT was
  still set despite the compiled false resource). Removing its single cache
  record and rebooting confirmed the diagnosis. New partition fingerprints
  let PackageManager evict stale caches through its existing implementation;
  no framework cache policy is weakened or disabled.
- KernelSingleProcessCpuThreadReader now checks the existing immutable eBPF
  capability before using the native BPF reader. Unsupported frequency count
  returns zero and usage returns null. Mock readers remain enabled. This does
  not invent missing per-thread attribution; ordinary kernel CPU/UID counters
  remain unchanged.
- BatteryExternalStatsWorker only queries modem energy when an active modem
  exists; the mere presence of a TelephonyManager service is not sufficient.
- Settings checks for a process-state key before requesting a dimensional
  battery sum. Absent data uses its existing unavailable-value fallback
  without repeated exceptions; total per-app consumption and durations remain
  unchanged. No unsupported measurements are fabricated or enabled.
- Device I/O profiles explicitly retain default kernel scheduling rather than
  joining the absent blkio controller. CPU/cpuset profiles remain real. This
  adds no claim of I/O cgroup prioritization.
- Label the exact three charger/fuel-gauge type files and OTG online file as
  sysfs_batteryinfo,
  which health already has permission to read. Paths were resolved from the
  actual audit inode numbers and confirmed labeled generic sysfs beforehand.
  After the type labels were corrected, hardware exposed the subsequent OTG
  online read, resolved to its actual sysfs inode and labeled the same way.
  No broad sysfs or default-property permission is added.

Unidentified old vendor default-property reads and diagnostic Wi-Fi interrupt
messages are not treated as proven functional failures. They require precise
property identification or a reproducible symptom before further policy/driver
changes. Logs, private keys and userdata are not published.

## Validation

Source patches apply against clean pinned indexes, and the new init file passes
host_init_verifier. Full signed-image/layout/OTA checks and physical runtime
results are recorded separately; source edits alone do not establish success.

## Data initialization and update transition (2026-10-04)

An intermediate candidate's ordinary reboot returned to recovery with a missing
user-0 DE key version path. Read-only checks of unmounted userdata passed;
restoring candidate 8 and a real power-off with USB disconnected repeated the
failure. Its cause was not established. The user authorized TWRP Format Data.
Fresh initialization retained supported user/group quota, omitted unsupported
project quota, completed setup, and passed two ordinary candidate-10 reboots.
This transition removed the previous apps/data; it is not a retention claim.

Candidate 11 packages the Wi-Fi-only application flags correctly. Hardware
initially retained old PERSISTENT flags through a stale package parser cache.
Removing only its TeleService cache record and rebooting confirmed the source
fix: standard per-user state, application disabled, no persistence flag/process,
zero default-manager modems, encrypted data, SELinux Enforcing, GOOD signing,
empty crash buffer and no current-boot ANR/native tombstone. Browser rendering
also passed. Candidate 12 adds distinct release identity and the subsequent
exact OTG online label. The signed OTA passed image/layout/package/signature
checks and TWRP installation (updater RC 0, 43 seconds). Android automatically
replaced the old package parser cache. All 210 installed package/UID records
survived the update and ordinary reboot; no further data format was performed.

Both final boots pass encryption, user-0 DE key availability, SELinux Enforcing,
GOOD signing, all four exact health labels, and APK/framework/init hash readback.
TeleService stays installed in its default per-user state, but disabled and
nonpersistent by the manifest; no phone or modem process runs. The targeted
failure counts are zero. The ordinary reboot has no native tombstone,
current-boot ANR or crash-buffer entry. MobiCore receives SIGKILL before EFS
unmount succeeds; init shutdown takes 2414 ms without timeout. Browser page
rendering passes after reboot. The build remains userdebug with release-keys.

Installed ZIP SHA-256:
`80ac25b60c744836dbb225dfb81f64ce9ef1fc40e31557b67e8fe284c30c5286`.
Build number: `gta3xlwifi.20261004.132339`.

See [runtime and reboot results](usage-runtime-check.json),
[signed package checks](usage-release-signature-check.json),
[compatibility artifact checks](usage-compat-check.json),
[image layout](usage-native-layout-check.json), and
[port package checks](usage-port-package-check.json).
These scoped tests do not complete long-term or all-hardware validation.
