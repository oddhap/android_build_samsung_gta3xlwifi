# Isolated source-built candidate boot layout

The actual selected Ninja Samsung boot rule packages the pinned source-built
kernel7ece8d6f into a separate artifact outside TOP. No combined shell command,
production image write, kernel/input selection, recovery operation or signing is
performed. The existing actual device ramdisk checker passes, the raw kernel
payload hash matches exactly, and the normal SEANDROIDENFORCE trailer is retained.

Header1,2048-byte pages,zero ramdisk and enforcing command line match the actual
selected SAR boot rule. Output size25503760 bytes fits physical33554432-byte boot
partition with8050672 bytes margin. Selected Image/vendor21-MTP/DTBO remain exact.

This only verifies packaging/layout, not boot execution, DT/driver compatibility
on hardware, kernel/policy selection or a complete ROM. The artifact is not an
installation candidate and no flash-ready package is claimed.
