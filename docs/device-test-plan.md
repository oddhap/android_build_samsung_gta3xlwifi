# SM-T510: første native maskinvaretest

Dette er LineageOS 19.1 / Android 12L, en egen enhetsport for gta3xlwifi,
med kildebygget 4.4.302-kjerne og Samsungs originale CWA1-vendor. Ingen GSI
eller GApps skal installeres. Sikkerhetsnivået og stabiliteten er ikke dokumentert:
plattformens sikkerhetsdato er 2025-03-05 og vendorens er 2022-12-01.
Brukeren har godtatt sletting, Knox-endring og ustabilitet under testing.

## Før første flash

1. Full bygging må avsluttes med returkode 0. Kjør verify-native-images.py,
   check-native-vintf.py og check-stock-vendor-policy.py --runtime-mode på det
   ferdige bygget. Behold også de tidligere strenge kontrollrapportene.
2. Kopier ROM, boot, recovery, DTBO, vendor og product samt kontrollrapporter
   til Mac-en. Kontroller SHA-256 etter overføring. Original Samsung-fastvare
   skal være komplett og kontrollert lokalt for tilbakeføring.
3. Brukeren låser opp bootloaderen fysisk. Etter nullstilling må stockoppsettet
   kobles til Internett og OEM-opplåsing fremdeles være aktiv, normalt nedtonet.
   Aktiver USB-feilsøking på nytt. Kontroller via ADB at låsestatus faktisk endret
   seg; tillatelse til opplåsing alene er ikke det samme som en opplåst bootloader.
4. Kontroller Download Mode-skjermens OEM/FRP/KnoxGuard-status. Les nettbrettets
   PIT med Heimdall og lagre den. Sammenlign partisjonsnavn og størrelser med
   bildekontrollen før flash. Ingen repartisjonering inngår i planen.
5. Test-vbmeta er usignert, AVB-flagg 3, og må bare brukes med opplåst bootloader.
   Det slår av hash-/oppstartsverifisering for utvikling. Det endrer ikke SELinux.
   Original-vbmeta er bevart sammen med resten av stock-fastvaren.

## Installasjon og observasjoner

Den konkrete flashrekkefølgen bestemmes etter PIT- og Download Mode-kontrollen.
Første recovery-oppstart er en egen kontroll: riktig Lineage-grensesnitt,
skjerm/knapper, USB/ADB, partisjonsvisning og sideload. Installer deretter den
verifiserte native ZIP-en og nullstill data med recoveryens meny.

Ved første systemoppstart: lagre oppstartslogg, logcat og kernel-logg når ADB
blir tilgjengelig. Kontroller modell, Lineage-versjon, ABI, SELinux Enforcing,
montering av system/vendor/product/data, VINTF og eventuelle HAL-krasj.
Bevar datakryptering i oppsettet; hvis /data ikke fungerer, undersøk årsaken
før noen endring av krypteringskravet.

## Funksjonstest

- Wi-Fi: tilkobling, DNS, nettlesing, frakobling og tilkobling etter hvile.
- Nettverk: netd/NetworkStats, VPN, trafikkregnskap og brannmur med qtaguid.
- Skjerm og berøring: rotasjon, lysstyrke, flerberøring og lås/oppvåkning.
- Lyd: begge høyttalere, volum, mikrofon og hodetelefoner hvis tilgjengelig.
- Kamera: foran/bak, bilde og video, etterfulgt av ny åpning av kameraappen.
- Bluetooth: paring og lyd hvis brukeren har egnet tilbehør.
- Lagring: data vedvarer etter omstart; microSD, USB/MTP og lading.
- Kryptering: sett PIN, omstart og opplåsing; kontroller fscrypt/FBE-status.
- Hvile/batteri: kort hvile først, deretter nattest og temperatur/ladeforbruk.
- Flere kalde oppstarter, skjermlås og minst noen dagers vanlig bruk før noen
  påstand om stabilitet. Feil og manglende tester føres eksplisitt.

## Tilbakeføring

Bruk komplett, verifisert Samsung CWA1-fastvare med tilhørende BL/AP/CSC
og en data-nullstilling hvis tilbakeføring blir nødvendig. Ikke bland originale
og nye boot-/vbmeta-/systembilder. Ikke relås bootloaderen med utviklings-ROM.
Fysisk Download Mode må forbli tilgjengelig gjennom første test.

Referanser for Samsungs opplåsingsmekanisme og AVB-koden:

- https://topjohnwu.github.io/Magisk/install.html#unlocking-the-bootloader
- https://lineageos.github.io/lineage_wiki/devices/gts4lvwifi/install/
  (annen Samsung-modell; mekanisme som referanse, ikke SM-T510-bilder)
- Lineage-kilden external/avb/libavb/avb_slot_verify.c og
  system/core/fs_mgr/libfs_avb/fs_avb.cpp fra det låste kildemanifestet.
