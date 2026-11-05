# Android17 compiler oracle after restricted ownership assignment

The same independent strict-compiler membership checks as oracle01 now validate
all 524 property types with **zero unowned types**. Both counterfactual fixtures
compile as expected; no -N flag, permissive declaration or real-policy bypass is
used. The exact positive dependency graph and source/compiler hashes bind the
result to the new owner proposal. Original policy and source are not modified.

This is ownership membership validation only, not whole-policy security approval,
runtime property access, AV/MLS, boot or hardware validation. The actual combined
vendor policy still has strict errors recorded by the separate proposal reports.
