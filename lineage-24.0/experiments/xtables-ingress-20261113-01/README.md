# Two private ingress xtables extensions

Adds builtin bad_iif and ingress_discard to the prior seven real extensions.
Required arguments use strict decimal interface indices0..INT_MAX and32 lowercase
hex destination bytes. Unassigned zero/mapped-zero destinations are rejected;
formatters emit canonical numeric/hex arguments. No name/zone lookup or policy/
parent-rule installation occurs. The two UAPI structs match the built kernel.

76 actual callback/parser/saver assertions pass with fatal UBSan, including
integer overflow/sign/hex/whitespace rejection, invalid destinations, unchanged
payload on errors and exact save output. Host xtables API is a fixture; mandatory
option/inversion engine and real CLI/kernel execution are not claimed. The real
xtoptions.c string/mandatory behavior was also inspected read-only.

xtables-ingress-native-20261113-01 passes actual Android17 registry generation,
complete libext archive and full ARM64 iptables link. All79 original/new registry
symbols and final machine-code calls for the nine private descriptors agree;
original dynamic dependencies and source inputs remain unchanged. Complete1243/17
source audits before/after pass. Sequential ingress pipeline exit0 at03:39:05UTC
November13. No production binary replaced, rules executed or networking readiness.
