# Explicit compiled UID/app producer capability

Private bit13 distinguishes compiled dual-stack UID/app packet producers from
storage-only bit12. Both return zero without the actual product INET+IPV6 config.
Source identity checks preserve every accounting and packet body. Full build
checks both compiled ARM64 producer paths and all original output call sites.
The exact existing feature query is extended; no ioctl or wire layout changes.
SELinux capability bits/assertions remain unchanged. No source/prebuilt promotion,
installed rule, networking Ready or flash candidate is implied.
