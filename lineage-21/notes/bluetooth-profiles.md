# Bluetooth headphone audio backport

The November 12 LineageOS 21 ARM64 build did not set any `bluetooth.profile.*`
properties. At the pinned Bluetooth revision
`d5e3fad887c711169821ac269940ce94afe35bdd`, `A2dpService.isEnabled()` reads
`BluetoothProperties.isProfileA2dpSourceEnabled().orElse(false)`, and
`btservice/Config.java` uses that result to select profiles at startup. The
controller reaching ON did not establish that headphone media profiles started.

There was also no usable Bluetooth audio module in the built system/vendor.
Android 14 still has a legacy UIPC fallback, but its `audio.a2dp.default` module
was not packaged. Enabling profiles alone does not establish working playback.

## Backported changes

- Enable A2DP source, AVRCP target, battery, GATT, HID host, OPP and PAN using
  the profile settings from the LineageOS 24 runtime35 fix.
- Rebuild the reviewed SM-T510 HIDL 2.0 audio shim under `device/btaudio` against
  LineageOS 21. It registers `IBluetoothAudioProvidersFactory` in the same
  Samsung audio process as the stream, preserving the process-local session.
- Compose exactly three new vendor files: the ARM32 audio module, a HIDL 2.0
  VINTF fragment, and the Bluetooth audio policy. Change only the main audio
  policy's include from the old A2DP module to the Bluetooth module. Audit all
  other file contents, ownership, modes and SELinux labels for equality.

LE Audio and HFP microphone input remain disabled. This change targets classic
Bluetooth headphone media playback. It does not change the kernel or SELinux
policy. The existing MTP configuration and graphics donor libraries are retained.

The shim's source provenance is recorded in `btaudio/SOURCE_PROVENANCE.json` in
the device tree. The original implementation worked with headphone AAC playback
on LineageOS 24; that result is not a LineageOS 21 runtime test.

## Verification

`check-btaudio-shim-abi.py` requires an ARM32 ELF and resolves every dependency
and required dynamic symbol against VNDK v30 and the platform LLNDK libraries.
`compose-btaudio-vendor.py` and `audit-ext4-tree.py` enforce the exact vendor diff.
`verify-bluetooth-package.py` checks the actual signed profile properties, audio
policy, factory manifest, module hash and ABI against providers extracted from
the signed package, including its VNDK/runtime APEX payloads.

A newly signed ROM must pass these checks in addition to the established
release validators. Build and package results are recorded with the candidate;
source configuration alone is not confirmation of headphone pairing or playback.
The owner currently runs LineageOS 24 and is not downgrading for this test.

After installing the candidate on a LineageOS 21 test device:

1. Pair the reported headphones and a second model. Confirm they remain
   connected and play media, including pause/resume and volume changes.
2. Inspect A2DP/AVRCP state and logs for Bluetooth/audio crashes, provider
   registration failures, or audio module load errors.
3. Disconnect/reconnect, toggle Bluetooth, and reboot. Confirm saved headphones
   reconnect and audio returns to the tablet after disconnecting them.

Pairing, playback and reconnect behavior require physical LineageOS 21 testing.
