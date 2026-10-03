# Private signing for the SM-T510 port

The tested development ROM used Android's publicly available test certificates.
The Trust notification correctly warned about this. The signed update replaces
the APK, APEX container, APEX payload and OTA signing keys with persistent keys
specific to this project. Trust and signature checks are not disabled.

The build remains **userdebug**, with rooted ADB available when the owner enables
rooted debugging. Signing produces `release-keys` build tags. These tags describe
signing, not the `user`/`userdebug` build variant or official LineageOS status.

## Subsequent updates

Run `bash /srv/android/ports/lineage-21/tools/build-release.sh` on the build VM.
This builds target files and OTA tools, then runs `sign-release.py`. Plain `bacon`
still produces a test-key development package; do not install that over a
private-key installation without an explicit reverse migration.

Private keys live in `/srv/android/signing/gta3xlwifi`, outside the Android and
upload checkouts. The directory is accessible only to its owner and key files
have mode 0600. An additional local copy is retained in the ignored `.signing/`
directory. Neither private keys, the certificate map nor package inventories
belong in GitHub. Keep these keys: replacing them requires another migration.

The signer refuses incomplete key pairs or a changed certificate map. Keys are
reused rather than regenerated. Distinct old certificates map consistently to
distinct project certificates; modules sharing an old certificate retain that
relationship. Newly signed APEX payloads have separate 4096-bit RSA keys.
Presigned third-party and stock vendor modules retain their signatures.

## First migration from test keys

Follow LineageOS's key-migration approach: stop Android before changing its
package certificate database, retain an exact backup, migrate only known
certificate/key-set entries, then install the signed ROM in recovery.
`prepare-key-migration.py` takes a decoded `packages.xml`, a certificate map and
an output path. It validates that no unrelated XML attribute or node changes.
It rejects data APKs using old system certificates because their installed APKs
would otherwise disagree with the migrated database.

Android 14 uses binary ABX XML. Use Android's `abx2xml` and `xml2abx`, and verify
the binary-to-XML round trip before replacing `/data/system/packages.xml`.
Restore mode 0660, system:system ownership and the original SELinux context.
Never run migration repeatedly at boot or disable package signature checks.
The original package database and candidate 7 ROM permit rollback together.

## Verification

`verify-release.py` checks private APK/APEX container signatures, AVB signatures
of APEX payloads, and the OTA's whole-file CMS signature against the project
release certificate. It checks the tested boot image is byte-identical, the
critical platform fixes are unchanged, images fit the physical partitions, and
the OTA references only boot/system/product with no data formatting.

It exports `verified-target-files` and a separate `native-image-check.json` under
the release directory. Then run the existing layout and package checks against
these artifacts:

```sh
python3 tools/verify-native-layout.py --report-dir /srv/android/artifacts/lineage-21/release
python3 tools/verify-port-package.py --report-dir /srv/android/artifacts/lineage-21/release \
  --target-files /srv/android/artifacts/lineage-21/release/verified-target-files
```

Hardware boot, app inventory, encryption, SELinux, networking and Trust state
must also be checked after installation. Private signing does not change the
old Samsung vendor/kernel security coverage or certify the port as stable.

Reference: [LineageOS signing and key migration](https://lineageos.github.io/lineage_wiki/signing_builds.html).
