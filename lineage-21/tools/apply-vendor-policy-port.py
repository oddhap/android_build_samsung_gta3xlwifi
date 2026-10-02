#!/usr/bin/env python3
"""Keep Samsung's existing ISO/UDF genfs labels for this product only."""
from pathlib import Path
import subprocess
repo=Path('/srv/android/src/lineage-21.0/device/lineage/sepolicy')
expected='126b2bdd0f6fdc815999e44b9e134c7ae6c39d8c'
actual=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
if actual!=expected: raise SystemExit('Review changed Lineage policy revision: '+actual)
p=repo/'common/private/genfs_contexts';s=p.read_text()
before="genfscon iso9660 / u:object_r:iso9660:s0\ngenfscon udf / u:object_r:udf:s0"
after="ifelse(gta3xlwifi_stock_removable_fs, `true', `', `\n"+before+"\n')"
if after not in s:
    if s.count(before)!=1: raise SystemExit('Review changed removable filesystem labels')
    p.write_text(s.replace(before,after))
print('Preserved original Samsung ISO/UDF labels with a device-only policy condition.')
