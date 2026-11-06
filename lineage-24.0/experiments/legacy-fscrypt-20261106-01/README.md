# Legacy fscrypt: final init executable linkage

This is the same runtime proposal as legacy-fscrypt-20261105-02, with its
empty-key rejection and 88 clean fatal-sanitizer host cases. Candidate03 corrected
Soong string-valued select branches; this candidate moves the scoped defaults to
common init_defaults so the final init executable links the typed keyutils API.
The runtime source/header bodies remain byte-identical to the final host probe.

Snapshot port-20261106-01 passed the full 1,243-project/16-patch audit and exact
reverse-composition proof. The prior native build compiled but failed init linking;
that failure is preserved. Actual final compilation is legacy-fscrypt-native-20261106-01.
Inspect its exit and after-audit before claiming successful executable linkage.
verify-fscrypt-native.py verifies the installed outputs and both wrapper variants
after completion. No hardware keyring, ciphertext, TEE, rollback or boot validation
is implied. Original images, Lineage21, TWRP, firmware, signing material and data
remain protected. Network/policy integration and installer gates remain open.
