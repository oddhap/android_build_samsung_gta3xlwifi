#!/usr/bin/env python3
"""Read-only complete tracked-file hash audit for standalone kernel builds."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root=Path(sys.argv[1]).resolve(); output=Path(sys.argv[2])
if output.exists():
    raise FileExistsError(output)
def git(*args):
    return subprocess.check_output(['git','-C',str(root),*args])
files=git('ls-files','-z').decode().split('\0')
hashes={}
for name in filter(None,files):
    path=root/name
    # Git stores symlink target bytes, not the target's file contents.
    data=path.readlink().as_posix().encode() if path.is_symlink() else path.read_bytes()
    hashes[name]=hashlib.sha256(data).hexdigest()
result={'revision':git('rev-parse','HEAD').decode().strip(),
        'tree':git('rev-parse','HEAD^{tree}').decode().strip(),
        'tracked_sha256':hashes,
        'diff_sha256':hashlib.sha256(git('diff','HEAD','--binary','--full-index')).hexdigest(),
        'status':git('status','--porcelain','--untracked-files=all').decode().splitlines(),
        'scope':'Tracked source and Git revision/tree; untracked status recorded without reading private files'}
output.write_text(json.dumps(result,indent=2)+'\n')
print(f'Audited {len(hashes)} tracked kernel files: {output}')
