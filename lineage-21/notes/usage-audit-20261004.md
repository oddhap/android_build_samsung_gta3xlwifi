# Loggkontroll etter vanlig bruk – 4. oktober 2026

Nettbrettet har vært oppe i 19 timer og 41 minutter. Androids hovedprosess
(system_server, PID 4341) er den samme som etter den kontrollerte omstarten
3. oktober. Brukeren rapporterer fungerende videoavspilling og nettbruk.

## Stabilitet og systemstatus

- Ingen appkrasj, ANR-rapporter eller native-krasj fra denne oppstarten ble funnet.
  De 16 lagrede prosessavslutningene er normale bakgrunnsoppryddinger eller
  vellykket egen avslutning, uten registrerte krasj eller ANR.
- Datapartisjonen er skrivbar, med støttet bruker/gruppekvote og uten project
  quota. Filkryptering og SELinux Enforcing er aktive; Trust-signering er GOOD.
- Rundt 664 MiB minne var tilgjengelig. Ingen tegn til OOM, filsystemfeil,
  alvorlige mediefeil eller Wi-Fi firmware-panic ble funnet i de bevarte loggene.
- Wi-Fi har null HAL-, wificond-, supplicant- og hostapd-krasj og null
  LastResortWatchdog-utløsninger. Driveren logger enkelte WDT/interrupt-advarsler
  rundt vekking; dette er ikke i seg selv dokumentasjon på en Wi-Fi-krasj.
- Temperatur: batteri 23,4 °C, AP 24,7 °C, thermal status 0.
  Hvilemodus fungerer: 1091 vellykkede suspend-forsøk, 22 avbrutte forsøk og
  ingen resume-feil. Siste avbrudd er alarmtimer/EBUSY. Dette dokumenterer at
  hvilemodus fungerer, uten å etablere en batterilevetidsmåling.

## Ting som bør ryddes opp i

1. Mobiltelefoni-tjenester kjører fortsatt på Wi-Fi-modellen. RIL logger
   gjentatte unsupported getCurrentCalls-kall, og cpboot-daemon forsøker stadig
   å åpne modem-enheten /dev/umts_boot0 som ikke finnes. Dette skjer selv med
   ro.radio.noril=yes og ro.carrier=wifi-only. Ingen påvirkning på nettbruk er
   dokumentert; unødvendig bakgrunnsarbeid og loggstøy gjør dette til den
   tydeligste kandidaten for opprydding. Strømgevinsten er ikke målt.
2. Batteristatistikken mangler enkelte prosess-state-forbrukstall og CPU-
   frekvensdata. Dette kan redusere nøyaktigheten i forbruk per app; loggene
   viser ingen tilsvarende temperatur- eller ladefeil.
3. Enkelte gamle Samsung-tjenester møter SELinux/property-avslag, og noen
   blkio-profiler forsøkes på kontrolleren som denne kjernen ikke har. Ingen
   observerte funksjonsfeil er knyttet til disse meldingene.

Én eldre native-krasjrapport gjelder mcDriverDaemon 3. oktober kl. 14:42:32.
Den er markert isPrevious og ligger i signal_handler/thread::join. Tidspunkt
og stack tyder på avslutningsbanen ved den planlagte omstarten. Den har ikke
gjentatt seg i denne oppstarten; årsaken er ikke uavhengig reprodusert.

## Omfang

Kontrollen brukte logcat, dmesg, DropBox, prosessavslutningshistorikk, ANR/
tombstone-inventar, Wi-Fi-, batteri-, temperatur-, minne- og hvilemodusstatus.
Logcat og dmesg er sirkulære buffere og dekker ikke nødvendigvis hele perioden.
Vedvarende krasj- og avslutningshistorikk supplerer disse. Resultatet støtter
brukerens erfaring, men er ikke en full stabilitetssertifisering. ROM-en og
innstillingene er ikke endret; ADB returneres til vanlig shell etter kontroll.
Rålogger ligger bare lokalt. Se [strukturert resultat](usage-audit-20261004.json).
