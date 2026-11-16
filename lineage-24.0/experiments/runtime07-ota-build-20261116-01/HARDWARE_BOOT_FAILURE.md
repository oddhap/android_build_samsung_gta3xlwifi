# Encryption initialization advances; LMKD constructor aborts

Snapshot07 installed successfully with physical new-vold/FBE-fstab/static-stage/
cpuacct and boot/vendor/recovery readbacks. The actual enablefilecrypto command
now exits0. The next critical failure is LMKD: libmemevents global initialization
calls unchanged BpfUtils get_api_level_full(), which aborts when netbpfload.rc is
absent. That loader service is intentionally excluded on this kernel. Snapshot08
adds comments-only genuine platform version data, retaining no loader actions or
BPF-ready properties, and corrects kernel capability comparison to consult the
actual cached kernel version when below the platform minimum. Supported-kernel
results are unchanged. LMKD already supports the real in-kernel LMK interface;
no mock memory management, fake BPF readiness or policy bypass is introduced.
