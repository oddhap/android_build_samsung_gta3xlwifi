# Unused ramdisk experiment

These tools were an early investigation of bypassing Samsung skip_initramfs.
They are not part of the LineageOS 21 port or its build procedure. Android 14
still produces a physical system-as-root image, so the existing source-built
kernel and kernel-only boot image are retained. Do not use this experimental
kernel in the installation package.
