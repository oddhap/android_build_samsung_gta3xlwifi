#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seven CLI safety fixtures for the offline kernel checker, not kernel proof."""
import argparse
from pathlib import Path
import json
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owned', action='store_true', help='Test new private-ioctl kernel checker')
    args = parser.parse_args()
    tool = Path(__file__).resolve().with_name(
        'check-socket-owned-kernel.py' if args.owned else 'check-qtaguid-lifetime.py')
    with tempfile.TemporaryDirectory(prefix='qtaguid-lifetime-safety-') as d:
        d = Path(d)
        source, kout = d/'source', d/'kernel-output'
        source.mkdir()
        kout.mkdir()
        existing = d/'existing'
        existing.mkdir()
        (existing/'sentinel').write_text('unchanged')
        alias = d/'alias'
        alias.symlink_to(source, target_is_directory=True)
        cases = [source, source/'child', kout, kout/'child', alias/'child',
                 existing, d/'missing-input-report']
        for out in cases:
            result = subprocess.run(['python3', str(tool), '--objcopy', '/bin/false',
                '--objdump', '/bin/false', str(source), str(kout),
                str(d/'missing-image'), *([str(d/'missing-experiment')] if args.owned else []),
                str(out)], capture_output=True, text=True, timeout=10)
            assert result.returncode != 0, out
        assert not (source/'child').exists() and not (kout/'child').exists()
        assert (existing/'sentinel').read_text() == 'unchanged'
        assert sorted(p.name for p in existing.iterdir()) == ['sentinel']
        assert not json.loads((cases[-1]/'report.json').read_text())['passed']
    print('PASS: 7 CLI safety cases; protected source/output, aliases, no overwrite and failed input report')


if __name__ == '__main__':
    main()
