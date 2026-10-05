#!/usr/bin/env python3
"""Export all port changes and check each patch against a clean pinned index."""
from pathlib import Path
import hashlib, json, subprocess, tempfile
root=Path('/srv/android/src/lineage-21.0')
artifacts=Path('/srv/android/artifacts/lineage-21/source-patches')
artifacts.mkdir(parents=True,exist_ok=True)
projects=('frameworks/base','system/netd','system/bpf','packages/modules/Connectivity','packages/modules/DnsResolver','device/lineage/sepolicy','system/core','frameworks/av','frameworks/native','system/memory/libmeminfo','packages/apps/Settings','packages/services/Telephony','external/boringssl')
records=[]
for name in projects:
    repo=root/name
    revision=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    patch=subprocess.check_output(['git','-C',str(repo),'diff','--binary','--no-ext-diff','HEAD'])
    files=subprocess.check_output(['git','-C',str(repo),'ls-files','--others','--exclude-standard'],text=True).splitlines()
    for relative in files:
        p=repo/relative
        if not p.is_file(): raise SystemExit(f'Review unexpected untracked item: {p}')
        extra=subprocess.run(['git','diff','--no-index','--binary','--no-ext-diff','--','/dev/null',relative],cwd=repo,capture_output=True)
        if extra.returncode!=1: raise SystemExit(f'Cannot export new file: {p}')
        patch+=extra.stdout
    target=artifacts/(name.replace('/','_')+'.patch')
    target.write_bytes(patch)
    with tempfile.TemporaryDirectory(prefix='lineage21-patch-check-') as directory:
        subprocess.run(['git','clone','--quiet','--shared','--no-checkout',str(repo),directory],check=True)
        subprocess.run(['git','-C',directory,'read-tree',revision],check=True)
        subprocess.run(['git','-C',directory,'apply','--cached','--check',str(target)],check=True)
    records.append({'project':name,'revision':revision,'patch':target.name,
                    'sha256':hashlib.sha256(patch).hexdigest(),'new_files':files,
                    'clean_index_patch_check_passed':True})
(artifacts/'source-lock.json').write_text(json.dumps(records,indent=2)+'\n')
print('All platform patches exported and checked against clean pinned source indexes.')
