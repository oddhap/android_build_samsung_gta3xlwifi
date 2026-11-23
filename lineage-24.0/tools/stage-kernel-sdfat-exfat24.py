#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage the sdfat "exfat" filesystem alias for the isolated kernel candidate.

Android 17 vold only mounts exFAT public volumes when /proc/filesystems lists
"exfat" (system/vold/fs/Exfat.cpp IsSupported). Samsung's built-in sdfat driver
already implements exFAT but registers only as "sdfat". This adds a second
file_system_type named "exfat" that reuses the sdfat mount/kill_sb paths, as
later sdfat releases do with CONFIG_SDFAT_USE_FOR_EXFAT. No Kconfig/.config
change. Writes reference, candidate, patch and baseline.json into a new staging
directory; never touches the baseline tree.
"""
import difflib
import hashlib
import json
import sys
from pathlib import Path

NAME = 'fs/sdfat/sdfat.c'

FS_TYPE_OLD = '''\t.fs_flags    = FS_REQUIRES_DEV,
};

static int __init init_sdfat_fs(void)
'''
FS_TYPE_NEW = '''\t.fs_flags    = FS_REQUIRES_DEV,
};

/*
 * gta3xlwifi: also register as "exfat" so Android vold (Exfat::IsSupported
 * checks /proc/filesystems for "exfat") can mount exFAT public volumes with
 * the built-in sdfat driver. Same mount and teardown paths as "sdfat".
 */
static struct file_system_type exfat_fs_type = {
\t.owner       = THIS_MODULE,
\t.name        = "exfat",
\t.mount       = sdfat_fs_mount,
#ifdef CONFIG_SDFAT_DBG_IOCTL
\t.kill_sb    = sdfat_debug_kill_sb,
#else
\t.kill_sb    = kill_block_super,
#endif /* CONFIG_SDFAT_DBG_IOCTL */
\t.fs_flags    = FS_REQUIRES_DEV,
};

static int __init init_sdfat_fs(void)
'''
REG_OLD = '''\terr = register_filesystem(&sdfat_fs_type);
\tif (err) {
\t\tpr_err("[SDFAT] failed to register filesystem\\n");
\t\tgoto error;
\t}

\treturn 0;
'''
REG_NEW = '''\terr = register_filesystem(&sdfat_fs_type);
\tif (err) {
\t\tpr_err("[SDFAT] failed to register filesystem\\n");
\t\tgoto error;
\t}

\terr = register_filesystem(&exfat_fs_type);
\tif (err) {
\t\tpr_err("[SDFAT] failed to register exfat alias\\n");
\t\tunregister_filesystem(&sdfat_fs_type);
\t\tgoto error;
\t}

\treturn 0;
'''
UNREG_OLD = '''\tsdfat_destroy_inodecache();
\tunregister_filesystem(&sdfat_fs_type);

\tfsapi_shutdown();
}
'''
UNREG_NEW = '''\tsdfat_destroy_inodecache();
\tunregister_filesystem(&exfat_fs_type);
\tunregister_filesystem(&sdfat_fs_type);

\tfsapi_shutdown();
}
'''


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if len(sys.argv) != 3:
        print('usage: stage-kernel-sdfat-exfat24.py BASELINE_SRC NEW_STAGING_DIR', file=sys.stderr)
        return 2
    baseline, staging = map(Path, sys.argv[1:])
    if staging.exists():
        raise SystemExit(f'staging exists: {staging}')
    original = (baseline / NAME).read_text()
    candidate = original
    for old, new in [(FS_TYPE_OLD, FS_TYPE_NEW), (REG_OLD, REG_NEW), (UNREG_OLD, UNREG_NEW)]:
        assert candidate.count(old) == 1, ('anchor not unique', old[:60])
        candidate = candidate.replace(old, new)
    assert 'exfat_fs_type' not in original and candidate.count('&exfat_fs_type') == 2
    target = staging / NAME
    target.parent.mkdir(parents=True)
    (staging / (NAME + '.reference')).write_text(original)
    target.write_text(candidate)
    patch = ''.join(difflib.unified_diff(original.splitlines(True), candidate.splitlines(True),
                                         'a/' + NAME, 'b/' + NAME))
    (staging / 'sdfat-exfat-alias.patch').write_text(patch)
    (staging / 'baseline.json').write_text(json.dumps({
        'baseline_kernel': str(baseline),
        'original_sha256': {NAME: sha(original.encode())},
        'candidate_sha256': {NAME: sha(candidate.encode())},
        'patch_sha256': sha(patch.encode()),
        'kconfig_changed': False,
    }, indent=2) + '\n')
    print(patch)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
