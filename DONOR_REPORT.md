# ARM64 donoranalyse — SM-T510

Kontrollert 6. oktober 2026. Dette er et statisk beslutningsgrunnlag for en
maskinvarekandidat. ARM64-oppstart og grafikk er ennå ikke fysisk bekreftet.

## Låst donor og utgangspunkt

Samsung SM-A305GT, ZTO:
`A305GTVJU8CWE1/A305GTOWO8CWE1/A305GTVJU8CWE1/A305GTVJU8CWE1`.
Firmwarearkivets SHA-256:
`75db4b7cf5d8b0d43e528a2aa874611edf8c26c32c1ff24a62595bd60459d641`.
Hentet med samloader 2.2.0. Ingen firmwarebinær ble kjørt under ELF-analysen.
Image- og filhashene finnes i `reports/arm64/firmware-lock.json` og
`reports/arm64/donor-summary.json`.

Kernel, vendor, DTBO, publisert ARM32-ROM, TWRP og vbmeta har riktige SHA-256.
Publiserte integrasjons-, device-, kernel- og vendor-repos har forventet commit
og rent arbeidstre. Se `reports/arm64/baseline.json`.

Nettbrettet kjører Android 14-build `gta3xlwifi.20261005.180749` med ARM32-app-ABI,
FBE og SELinux enforcing. `/proc/config.gz` viser ARM64, COMPAT, Mali r26p0 og
ION aktivert. TWRP-payloaden og dens normaliserte hash stemmer med handoffen.
Partisjonskopier og runtimeopplysninger oppbevares privat.

## Grafikk og buffergrensesnitt

Donorens ARM32-varianter av følgende filer er byte-identiske med stock SM-T510.
De første tre er også kontrollert på den tilkoblede enheten:

- `lib/hw/gralloc.exynos7904.so`
- `lib/hw/android.hardware.graphics.mapper@2.0-impl.so`
- `lib/libion_exynos.so`
- `lib/hw/hwcomposer.exynos7904.so`
- `lib/hw/android.hardware.graphics.allocator@2.0-impl.so`

Begge Mali-brukerromsbibliotekene oppgir `r26p0-01eac0`. Kernelens valgte
`b_r26p0`-driver har samme release og UK ABI 11.27. ION har compat-ioctl-
håndtering. Dette støtter et forsøk med donorens ARM64-klientbiblioteker og
de eksisterende ARM32 allocator/composer-tjenestene.

Disassemblering av `mali_gralloc_reference_retain` i stock ARM32 og donor ARM64
viser samme native-handle-versjon 12, samme sum av FD-/intfelt (`0x41`),
samme magic (`0x03141592`) ved `0x20`, og samme PID-/referansefelt ved
`0xcc`, `0xd0` og `0xd4`. Fysisk testing av allokering/import i begge retninger,
strides, formater, fences og ION-operasjoner gjenstår.

## Avhengigheter og namespaces

Donorlaget har 10 ordinære filer og to symlinker, totalt 55 978 904 byte
(53,4 MiB): Mali EGL/GLES, mapper 2.0, Exynos/default gralloc, memtrack,
RenderScript passthrough, Exynos ION, snap-biblioteket og vendorprogrammene
`boringssl_self_test64` og `snap_utility_64`. Vulkan og OpenCL peker til Mali.

Alle valgte ELF64-filer har en rekursiv DT_NEEDED-løsning. Ingen manglende sterke
importsymboler eller symbolversjoner er funnet i de undersøkte leverandørene.
Grafikk trenger VNDK-SP 30 og LLNDK; ingen særskilt åpning til VNDK-core er
funnet nødvendig. RenderScripts dynamiske `libRS_internal.so`, `libRSDriver.so`
og `libRSCpuRef.so` er inkludert i analysen og må dekkes av RS-/VNDK-oppsettet.

Bionic SDK og LLNDK-stubber gir foreløpig symbolgrunnlag. Den endelige kontrollen
må bruke bibliotekene og linkerconfig fra den bygde ARM64-ROM-en. Statisk
symboldekning beviser ikke namespace-tilgjengelighet eller runtimefunksjon.
Full rapport: `reports/arm64/dependency-closure.json`.

Donoren har ingen ARM64 `libMcClient.so`. Den eksisterende ARM32 TEE-stakken
beholdes, og den offentlige oppføringen avgrenses til `libMcClient.so 32`, som
støttes av Androids parser. `libOpenCL.so` finnes for begge ABI-er.

## Image og plass

Strategi: minimalt hybrid-vendor innen dagens partisjonsgrense, med beholdt
SM-T510 HAL-/TEE-/krypteringsoppsett.

| Måling | Byte |
| --- | ---: |
| Vendorgrense og utpakket image | 343 932 928 |
| Filsystemets brukte plass | 264 798 208 |
| Tilgjengelig filsystemplass | 61 521 920 |
| Sparse image | 265 669 400 |
| Hele donorens ordinære ELF64-libsett | 162 831 536 |

Donorfilene er kopiert med eier, mode og SELinux-xattrs. 960 eksisterende
stock-fil-/symlinkoppføringer er kontrollert. Bare tre tekstfiler er endret:
`default.prop` for zygote64_32/Bionic/Dalvik, `build.prop` for ABI-listene og
`etc/public.libraries.txt` for ARM32 TEE. Alle andre stock-filbytes, rettigheter,
eiere og labels er bevart. Ingen stock-policy, fstab eller USB-initfil er endret.
`e2fsck -f -n` består med returkode 0.

Sparse SHA-256:
`276777b5bde1dac2f31dbe9299c79e02c07486df6ff7b2ecad03cc722edee939`.
Raw SHA-256:
`4c320e8bfd9db294e4027acae204a8276c8f06d0e522654f668e38550eded7b9`.
Se `reports/arm64/vendor-image-report.json` for før/etter-hash og labels.

## Bygg- og valideringsstatus

ARM64-kildekopien er synkronisert og alle 1430 prosjekter er kontrollert mot
manifestet. Alle 13 plattformpatcher er validert og anvendt. Produktet bruker
`core_64_bit.mk`, ARM64 primærarkitektur, ARM sekundærarkitektur og reelle
BoringSSL-selvtester for begge ABI-er. Recovery-header-helperen forblir ARM32.

Fullbygg, signatur-/image-/pakkekontroller, VINTF og runtime-policy-link er
fullført. Vendor-installasjon med monteringskontroll og fysisk tilbakeføring
inkludert vendor passerer. Den gamle ARM32-ROM-ZIP-en alene gjenoppretter ikke
vendor. Fysiske ARM64-resultater og testbegrensninger står nedenfor.

## Referanser

- [Ubuntu Touch donoruttrekk](https://github.com/zyhazz/ubuntu-touch-sm-t510/blob/6267064ac27b6b5130c1ae553a360ddd69b3c19f/scripts/extract-firmware.sh)
- [Ubuntu Touch hybridmetode](https://github.com/zyhazz/ubuntu-touch-sm-t510/blob/6267064ac27b6b5130c1ae553a360ddd69b3c19f/scripts/make-hybrid-vendor.sh)
- Pinned Android: `system/linkerconfig/contents/namespace/sphal.cc`,
  `art/libnativeloader/public_libraries.cpp`,
  `hardware/interfaces/renderscript/1.0/default/Device.cpp`.
- Publisert kernel: `drivers/gpu/arm/b_r26p0` og
  `drivers/staging/android/ion/compat_ion.c`.

## Fysisk validering 7. oktober 2026

Den signerte kandidaten `gta3xlwifi.arm64.20261007.170546`, SHA-256
`f07e52c0f91a66fa1e5342ef3211e4fb8efdf709f1ac37d07994796b16203b3e`,
starter som native ARM64 med `zygote64_32` og SELinux enforcing. Både
ARM64- og ARM32-klienter består 120 shader-draws, window-buffer-swaps og
pixel-readback på Mali-G71. `/proc` bekrefter riktig process-ELF og mappet
Mali-vendor-driver for begge ABI-er. SurfaceFlinger er faktisk ARM64.

Kamera, lyd, akselerometer og DNS/TLS/HTTPS er også prøvd fra en faktisk
64-bit-app; begge kamera leverer seks frames, og AudioTrack spiller 44 100
PCM-frames til innebygd høyttaler. Alle 104 responsive baseline-HAL-grensesnitt
er bevart. Data/PIN, omstart, recovery-dekryptering og ARM32-tilbakeføring
passerer. Se `reports/arm64/arm64-validation-summary.json` for hashbundne rapporter.

Dette bekrefter den prøvde EGL/GLES-, mapper- og gralloc-kjeden. Vulkan, OpenCL
og RenderScript har statisk avhengighetskontroll, men ingen egen fysisk API-test.
Langtidstabilitet og video-/DRM-kodeker er heller ikke verifisert.
