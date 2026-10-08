# SM-T510: fungerende ARM64-kandidat

Native LineageOS 21 / Android 14 med ARM32-appstøtte er **bygget, signert,
installert og fysisk verifisert** på nettbrettet 7. oktober 2026. Nettbrettet er
nå tilbake i ARM64 Android etter recovery-testen. Testappene er fjernet;
brukerdata, EFS, DTBO og vbmeta er bevart. Recovery er senere oppdatert
med rettelsen for automatisk dekryptering uten PIN. Nettbrettet står nå uten PIN.

Dette er en fungerende eksperimentell kandidat. Langtidstabilitet og alle
maskinvarefunksjoner er ikke ferdig vurdert.

PIN-fri TWRP er også installert og fysisk verifisert, både uten PIN og med
PIN. Se [TWRP_PINFREE.md](TWRP_PINFREE.md) og det separate, hashbundne
[recovery-resultatet](reports/twrp-pinfree/validation-summary.json).

## Kandidat

- Fil: `artifacts/release/lineage-21.0-20261007-UNOFFICIAL-gta3xlwifi-arm64-privatekeys.zip`
- Build: `gta3xlwifi.arm64.20261007.170546`
- Størrelse: **912 222 234 byte**
- SHA-256: `f07e52c0f91a66fa1e5342ef3211e4fb8efdf709f1ac37d07994796b16203b3e`
- ABI: `arm64-v8a,armeabi-v7a,armeabi`; `zygote64_32`
- SELinux: **Enforcing**; brukerlagring: **encrypted/file**
- Eksisterende signeringsmateriale: alle 328 filer uendret; ingen nøkkelrotasjon.

Samlet, hashbundet resultat: [arm64-validation-summary.json](reports/arm64/arm64-validation-summary.json).

## Verifisert

| Kontroll | Resultat |
|---|---|
| Fullt target-files/otatools-bygg og åtte sluttkontroller | PASS |
| Signerte APK/APEX/OTA, partisjonsgrenser og faktisk image-layout | PASS |
| Native prosesser | init, system_server, SurfaceFlinger, zygote64, vold, audioserver, cameraserver og netd er ARM64 |
| ARM64- og ARM32-grafikk | Begge tegner 120 frames med swaps og korrekt pixel-readback på Mali-G71; riktig vendor-driver er mappet |
| Wi-Fi og appnettverk | Internett-ping samt DNS/TLS/HTTPS fra faktisk 64-bit-app passerer |
| Kamera | Front og bak leverer seks frames hver til 64-bit-app; ingen bilder lagres |
| Lyd | 44 100 PCM-frames spilles til innebygd høyttaler; ingen opptak |
| Akselerometer | Tre plausible sensormålinger mottatt av 64-bit-app |
| Bluetooth | Kontroller når STATE_ON; opprinnelig innstilling bevart |
| Bevarte HAL-er | Alle 104 responsive baseline-grensesnitt er fortsatt responsive |
| PIN/FBE og omstart | Opplåsing og lesbar CE-lagring etter begge ARM64-oppstarter |
| Skjerm av/på | PASS uten Zygote-restart; kernel deep suspend er ikke prøvd |
| TWRP etter ARM64 | Oppdatert 3.7.1_12: to PIN-frie oppstarter og én PIN-test passerer; reell CE-lesing/skriving og Android-retur verifisert |
| Tilbakeføring | Original vendor kontrollert ved full tilbake-lesing; ARM32-boot, enforcing, PIN/CE og Mali-grafikk passerer |

De detaljerte rapportene er referert fra sammendragsfilen. Rå Android-, kamera-,
nettverks- og recovery-logger samt alle data-/EFS-backuper ligger privat.

## Implementasjon og sporbarhet

ARM64 er hovedarkitektur og ARM32 sekundær. Eksisterende kernel 4.4.302 og DTBO
er beholdt. Et minimalt A305GT-basert hybrid-vendor legger til nødvendige
64-bit Mali/gralloc/mapper/ION-biblioteker; eksisterende 32-bit Samsung-HAL-er
og vendor-policy er bevart. Se [DONOR_REPORT.md](DONOR_REPORT.md).

Alle 1 430 kildeprosjekter er låst, og de 13 eksisterende plattformpatchene er
anvendt i det isolerte ARM64-treet. Pakkede 32-/64-bit-varianter, VNDK-SP,
donorimports og faktisk signert WebView med begge ABI-er er kontrollert.
WebView ligger på system for å passe den faste product-partisjonen.

Første OTA-forsøk stoppet før image-skriving fordi `unmount()` feiler når vendor
allerede er avmontert. Hooken kontrollerer nå `/proc/mounts` før alle writes;
montert og avmontert vendor er fysisk prøvd i TWRP. Første installerte kandidat
avdekket deretter at Samsungs ARM32 ODM-egenskaper vant over vendor/system.
Produktet deklarerer nå hele ABI-listen med `PRODUCT_PRODUCT_PROPERTIES`.
Verifikatoren følger inits faktiske prioritet og avviser den gamle kandidaten.
Historiske forsøksrapporter beholdes under `artifacts/attempts/20261007-170027`.

Den statiske ARM64 OTA-updateren kjører i eksisterende ARM32 TWRP. Den statiske
ARM32 header-helperen bevarer recovery-payloaden. VINTF og runtime-policy-link
passerer. Samsungs gamle vendor-policy feiler den strengere kryssversjons-
neverallow-kontrollen også i ARM32-baseline; policyflaggenes baseline er bevart,
uten nye permissive-domener. Fysisk enforcing er nå bekreftet på ARM64.

Komplett råbackup av userdata/EFS fra før ARM64-installasjonen, med den
daværende midlertidige PIN-en, er verifisert med full rå lengde, gzip-CRC og
SHA-256. Alle fem små partisjonskopier har eksakt fysisk
lengde og direkte verifisert hash; opprinnelige ADB-strømmer med dd-teksthaler
beholdes privat. [ROLLBACK.md](ROLLBACK.md) beskriver tilbakeføring uten
formatering. [BUILD_ARM64.md](BUILD_ARM64.md) beskriver bygg og testkommandoer.
Gjennomgåbare endringer ligger i `source-audit/arm64-changes`, `tools` og `tests`.

## Begrensninger

Bluetooth-paring/lyd mot annet utstyr, mikrofonopptak, video-/DRM-kodeker,
langtidstabilitet og kernel deep suspend er ikke verifisert. Disse begrenser
en stabilitetskonklusjon, selv om de prøvde grunnfunksjonene fungerer.

Den tidligere TWRP-loopen uten PIN er rettet i den nye recoveryen og fysisk
retestet. Den opprinnelige ROM-ZIP-en inneholder forrige header-helper; den
bevarer den nye recoveryen som ukjent. Recoveryens header er allerede riktig
for denne ROM-en. Neste ROM-bygg bruker den utvidede helperen med begge kjente
recovery-identiteter. Se [TWRP_PINFREE.md](TWRP_PINFREE.md).

## Byggemaskin

- Kilder: `/srv/android/src/lineage-21.0-arm64`
- Integrasjon: `/srv/android/ports/lineage-21-arm64`
- Artefakter: `/srv/android/artifacts/lineage-21-arm64`
- Logger: `/srv/android/logs/lineage-21-arm64`

ARM32-kilder og publisert baseline er beholdt separat. ARM64-arbeidet er lokalt
på egne grener; ingen GitHub-publisering er utført.
