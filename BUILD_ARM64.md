# ARM64-bygg for SM-T510

Arbeidstreet er isolert på Linux-byggemaskinen i
`/srv/android/src/lineage-21.0-arm64`. Integrasjonen ligger i
`/srv/android/ports/lineage-21-arm64`, og utdata i
`/srv/android/artifacts/lineage-21-arm64`. Eksisterende ARM32-tre og release
er separate. Kilder og donor er låst; se `DONOR_REPORT.md` og rapportene.

## Nytt bygg

Etter synkronisering, plattformpatcher og staging av de verifiserte inputene:

```sh
bash /srv/android/ports/lineage-21-arm64/build-arm64-candidate.sh
```

Det første steget bygger og kontrollerer begge native ABI-er, den statiske
ARM32 recovery-header-helperen og separate test-APK-er. Deretter bygges
`target-files-package` og `otatools`. Fullbyggets resultat står i
`/srv/android/logs/lineage-21-arm64/full-build.exit`.

WebView flyttes til `system` med byggsystemets eksisterende
`PRODUCT_FORCE_PRODUCT_MODULES_TO_SYSTEM_PARTITION`. Begge WebView-ABI-er
beholdes; `product` beholder sin fysiske størrelse på 327 155 712 byte.
Produktet deklarerer også ABI-listene via `PRODUCT_PRODUCT_PROPERTIES`: init
prioriterer product før Samsungs bevarte ARM32 ODM-egenskaper. Multilib-
kontrollen leser alle disse egenskapene og kontrollerer den effektive listen.

## Signering og sluttkontroll

Kjør på byggemaskinen etter vellykket fullbygg:

```sh
python3 /srv/android/ports/lineage-21-arm64/lineage-21/tools/sign-release.py \
  /srv/android/src/lineage-21.0-arm64/out/target/product/gta3xlwifi/obj/PACKAGING/target_files_intermediates/lineage_gta3xlwifi-target_files.zip
bash /srv/android/ports/lineage-21-arm64/lineage-21/tools/validate-arm64-candidate.sh
```

Signeringen krever eksisterende prosjekt-nøkler. Den oppretter eller roterer
ikke nøkler. Sluttkontrollen stopper ved første feil og kontrollerer blant
annet signaturer, fysiske partisjonsgrenser, signerte filsystemer, begge ABI-er,
donor-avhengigheter, statisk ARM64 OTA-updater og statisk ARM32 header-helper.
`release/offline-validation.json` opprettes først når alle stegene passerer.

Kjør også VINTF- og policy-kontrollene mot det faktiske hybrid-vendor-imaget.
Kryssversjons-neverallow-begrensningen er beskrevet i `BUILD_STATUS.md`.
Runtime-policy-link er separat fra fysisk SELinux-enforcing-kontroll.

## Nettbrettet

Bruk den eksisterende TWRP og fremgangsmåten i `ROLLBACK.md`. OTA-en skriver
boot, system, product og hybrid-vendor. Vendor må være avmontert; OTA-hooken
kontrollerer dette før partisjonsskriving. Data skal beholdes.

Etter oppstart og opplåsing kan den separate Mac-kontrollen kjøres:

```sh
adb root
python3 tools/check-device-arm64.py \
  --release-check artifacts/release/release-signature-check.json
```

Den krever riktig signert build-identitet, enforcing, kryptert data og et
opplåst skjermbilde. Den kontrollerer faktiske zygote-/SurfaceFlinger-prosesser
og kjører 120 shader-draws med window-buffer-swaps og pixel-readback fra både
ARM64- og ARM32-app. Test-APK-ene skal ligge i `artifacts/hardware-tests` og
ha hashene fra `artifacts/targeted-abi-check.json`. Rå diagnostikk lagres privat.

En bestått grafikk-/ABI-kontroll er ikke en full maskinvaretest. Oppstart,
PIN/FBE, recovery-dekryptering, nettverk, lyd, kamera, strømstyring og
tilbakeføring må vurderes og dokumenteres før en stabilitetskonklusjon.

## Separat maskinvaretest

`tests/hardware-probe` kopieres til device-treets `hardware-probe`-mappe og
bygges med `build-arm64.sh gta3xlwifi_hardware_probe`. Modulen er en
`android_test_helper_app` utenfor `PRODUCT_PACKAGES`. APK-en og en SHA-256-
rapport legges i `artifacts/hardware-tests` og
`artifacts/hardware-probe-build-check.json` på Mac-en.

Etter grafikkkontrollen kjøres `python3 tools/check-device-hardware.py`. Den
kontrollerer at responsive baseline-HAL-er fortsatt er responsive, Wi-Fi-
tilkobling/internett, DNS/TLS/HTTPS fra appen, faktisk 64-bit testprosess,
akselerometer, fremgang i
lydutgang og seks kameraframes fra både front og bak. Testappen får CAMERA
til dette forsøket; ingen bilder eller lydopptak lagres. Paring med Bluetooth
og langtidstabilitet dekkes ikke av denne testen.
