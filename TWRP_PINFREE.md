# SM-T510: PIN-fri TWRP

Installert og fysisk verifisert 7. oktober 2026. Nettbrettet er tilbake i
ARM64 Android uten PIN, med automatisk CE-opplåsing og kryptering beholdt.

Ny recovery: [recovery-twrp-sm-t510.img](https://github.com/oddhap/android_build_samsung_gta3xlwifi/releases/tag/lineage-21.0-arm64-beta-20261007).
TWRP-versjonen vises fortsatt som `3.7.1_12`.

- SHA-256: `e6dcc17e478de9d1d3f1c398fd10c9bc9d7ac80e546f18f58cd20d52766485b4`
- Størrelse: 38 981 648 byte, innenfor recovery-partisjonen på 47 185 920 byte.
- Oppstartshode: Android 14 / 2026-09-01, som den installerte ARM64-ROM-en.
- Samme recovery-kernel, DTBO, grafikkbibliotek, FBE-oppsett og lagrede innstillinger.
- Eksisterende userdata og EFS er beholdt. Ingen formatering eller deaktivering av kryptering.

## Årsak og rettelse

Den gamle recoveryen krasjet med `SIGSEGV` ved automatisk dekryptering uten PIN.
Recovery startet keystore2 etter å ha lagt Androids databasekopi i tmpfs, og
tolket `init.svc.keystore2=running` som at Binder-tjenesten var tilgjengelig.
Krasjet kom 2–20 ms etter tjenestestart; registreringen kom først senere.
Kodebanen brukte den tomme tjenestepekeren uten kontroll. Med PIN ga ventingen
på brukerens inntasting normalt tjenesten tid til å registrere seg.

Rettelsen venter avgrenset på den faktiske Binder-tjenesten og kontrollerer
alle nødvendige tjeneste-/operasjonspekere og resultatlengder. Ved feil forblir
lagringen låst, uten å dereferere en tom peker.

Uten PIN brukte den gamle koden også en delvis uinitialisert 32-byte-token.
Android 14 fyller de resterende bytene med nuller, slik den lokale ROM-kilden
og [AOSP-koden](https://android.googlesource.com/platform/frameworks/base/+/2907102b7b3b4a2c12ec5fd6dcb6f88c0ede82d8/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java)
viser. Recoveryen gjør nå det samme.

GCM-laget behandler de siste 16 bytene som autentiseringstag og krever vellykket
autentisering før FBE-nøkkelen avledes. Det tidligere laget ignorerte feil fra
sluttkontrollen. Krypteringsalgoritmer og Androids nøkkelfiler er ellers uendret.

## Verifisering

- Separat recovery-tre og egne byggfiler; opprinnelig recovery-kilde og image er uendret.
- Alle opprinnelige kontroller av image-layout, kernel, DTBO, header, FBE,
  oppstartsrekkefølge og 123 ELF-avhengigheter passerer.
- Faktisk GCM-kode passerer NIST AES-256-GCM-vektor, avviser endret tag/innhold
  og avkortet input, og passerer ASan/UBSan. Androids nullutfylling kontrolleres.
- Første PIN-frie recovery-oppstart: automatisk CE-dekryptering, stabil prosess,
  ingen fatale signaler, faktisk CE-SQLite-header og lesing/skriving i brukerlagring.
- Alle 13 kontrollerte krypteringsfiler er identiske gjennom recovery-testen.
  Etter Android-omstart er 12 vedvarende filer identiske; `per_boot_ref` fornyes
  normalt ved ny Android-oppstart.
- Android starter samme native ARM64-build med FBE og SELinux Enforcing;
  filen skrevet i TWRP er lesbar i Android.
- PIN-regresjon: lagringen er låst før PIN-inntasting; korrekt PIN åpner CE-lagring
  og TWRP-hovedmenyen. Ingen krasj eller endringer i krypteringsfilene.

Avsluttende PIN-fri recovery-oppstart passerer også: 13 målinger over mer enn
ett minutt uten prosessrestart, reell CE-lesing/skriving og uendrede nøkkelfiler.
Android starter uten PIN, med fem kontrollerte faktiske ELF64-prosesser; boot,
vendor, DTBO og vbmeta er identiske med før recovery-byttet. Testfilen er fjernet.

Detaljert sluttresultat: [validation-summary.json](reports/twrp-pinfree/validation-summary.json).
Rå logger, databaseheader, nøkkelfingeravtrykk og full recovery-backup ligger i
`.private/twrp-pinfree/` og skal ikke publiseres.

## OTA-integrasjon

Header-hjelperen i ARM64-kilden er utvidet med den nye recoveryens nøyaktige
payload-identitet. Bare OS-ordets fire byte unntas fra hashkontrollen. Begge
kjente recoverybilder passerer fixturetester for oppdatering, avvisning av
nedgradering, bevaring av payload og tilbakeføring ved injisert skrivefeil.
Den nye statiske ARM32-hjelperen er også kjørt fysisk i TWRP: preflight og
allerede synkronisert apply passerer; hele recovery-partisjonen er identisk før
og etter.

Den eksisterende, fysisk testede ARM64-ROM-ZIP-en med SHA-256 `f07e52c0…` er
beholdt byte-for-byte. Den inneholder forrige header-hjelper og vil behandle
denne nye recoveryen som ukjent og bevare den. Nye ROM-bygg bruker den utvidede
hjelperen. Den nye recoveryens header er allerede riktig for den installerte ROM-en.

## Kilder og reproduksjon

- [Rettelsesverktøy](tools/fix-twrp-pinfree.py)
- [Recovery-diff](source-audit/twrp-pinfree/pinfree.patch)
- [Byggverktøy](tools/build-twrp-pinfree.sh)
- [Image-kontroll](tools/verify-twrp-pinfree-image.py)
- [GCM-regresjon](tools/test-twrp-pinfree.py)
- [Header-hjelper med begge identiteter](source-audit/twrp-pinfree/recovery_header_sync.cpp)
- [Header-regresjon](tools/test-twrp-header-pinfree.py)
- [Partisjonssikret installasjon](tools/install-twrp-pinfree.py)

Linux-tre: `/srv/android/src/twrp-12.1-pinfree`.
Bygg-/testverktøy: `/srv/android/ports/twrp-pinfree`.
Kildegrunnlag: samme låste TWRP 12.1-manifest som den tidligere FBE-porten.
Bare `system/vold/Decrypt.cpp` er endret i recovery-koden.

Dette er fysisk prøvd på dette SM-T510 med eksisterende kryptert user 0 og
LineageOS 21 / Android 14. Andre brukere, firmware, passordtyper og
sikkerhetsdatoer er ikke verifisert av denne testen.
