# Real Android17 qtaguid accounting component

The complete native module passed isolated ARM64 CFI/APEX31 compilation/linking,
retaining all 44 original dynamic definitions, SONAME and NEEDED libraries; seven
internal definitions were added. Actual Android17 Java typechecking passes for
the complete tiramisu Connectivity module (101 sources, 306 classes), using the
real JDK21/system module/classpath/generated sources. Four Android regression
cases are included but not executed on Android.

The real kernel-schema parser passes 36 fatal-sanitizer cases. The initial whole
adapter passes 20 more cases on Mac/Linux, including preservation of aggregate
outputs after malformed/missing reads, close errors and overflow. These use
synthetic FILE contents and do not establish live counters or networking.

Snapshot03 integrates exactly eight reviewed native/Java files: 1,243 unchanged
project revisions, 17 exact patches, all 16 parent patches byte-identical. The
actual project build03 then completed exit0 (5m59/25 Ninja actions) with full
before/after source audits. Actual expanded-APEX ARM64 library exports match the
isolated module; real ARM32 static archives independently link to ELF32/EM_ARM;
the real JAR contains the new accounting path. Original kernel/vendor/DTBO inputs
remain unchanged. A private phony Java target-name error was corrected by targeting
the concrete Soong JAR. The plain-Ninja attempt was stopped before compilation;
its interrupted status and initial EXIT-trap misrecording are explicitly archived.

Subsequent source review found the missing procfs statistics group initialization.
The access fix in `network-stats-access-20261106-01` supersedes this runtime
adapter; current active snapshot is port-20261106-04. It rejects partial tables
instead of treating them as complete device accounting. No loader, BPF readiness,
firewall owner, LNA or DNS-owner bypass was introduced by either integration.
No packaged APEX/ROM candidate or live counter validation is claimed.
