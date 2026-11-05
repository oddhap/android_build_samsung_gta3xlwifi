# Narrow three old app-private-data grants

This isolated proposal follows the restricted property-owner candidate. It removes
exactly three forbidden old vendor grants: system_app searching privapp_data_file,
system_server renaming app_data_file, and the MLS-trusted attiqi_app executing
app_data_file. Current Android17 mlstrustedsubject assertions forbid these
operations. Domain classifications, labels, MLS constraints and every other
vendor statement remain unchanged. No allow is added.

Strict diagnostics decrease **67 -> 65**, with two resolved and no new diagnostic
assertion identities. All **5,918 assertion/constraint records** remain exactly in
the token inventory, including the new property writer restriction. The complete
vendor rule inventory now has 12,517 allow, 127 allowx, 132 neverallow and two
neverallowx statements. No permissive declaration is added.

Only vendor CIL changes among compiler inputs; every other hash and the compiler
are identical. Full 1,243-project/15-patch before/after source audits match.
Secilc255 remains strict failure, regardless of runner0 experiment completion.
The final verbose strict run records all remaining matching grants, with no
first-four truncation. No -N compilation or policy-security approval is used.

The candidate remains outside active source, snapshots, images and cache hashes.
Runtime app behavior, labels, HALs, networking/BPF, module ABI and Android17
FBE/installer/rollback remain gates. This produces no flashable ROM or device
operation. Existing MTP vendor, original kernels, TWRP and signing material remain
unchanged.
