# Physical boot reached vold but encryption initialization crashed

Snapshot06 installed successfully and physical root/acct context, static-stage
hash, boot/vendor/recovery readbacks pass. It advances beyond the previous cgroup
failure: ueventd, bootstrap APEX, servicemanager, vold, keymaster and keystore start.
SELinux audit records permissive=0. Actual vold SIGSEGV PC0x32294, matching build
ID7bc1446b95cf74d936782ab3563ac57b, symbolizes to FsCrypt.cpp:392: the wrapped
metadata-key predicate unconditionally dereferences a missing /metadata fstab
entry. This tablet has valid legacy FBE without a metadata partition. Snapshot07
adds the null check while retaining /data file encryption, configured flag values,
policy and kernel/vendor inputs. No automatic wipe, encryption disablement or
fake wrapped-key support is accepted. The owner returned the tablet to preserved
TWRP; raw persistent crash logs remain private.
