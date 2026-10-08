#!/usr/bin/env python3
"""Reuse all original TWRP layout/crypto checks against the isolated candidate."""
from pathlib import Path

baseline = Path('/srv/android/verify-twrp-image.py').read_text()
assert baseline.count("checkout = root / 'src/twrp-12.1'") == 1
assert baseline.count("destination = root / 'artifacts/twrp-sm-t510'") == 1
baseline = baseline.replace("checkout = root / 'src/twrp-12.1'",
                            "checkout = root / 'src/twrp-12.1-pinfree'")
baseline = baseline.replace("destination = root / 'artifacts/twrp-sm-t510'",
                            "destination = root / 'artifacts/twrp-pinfree'")
baseline = baseline.replace("logs/twrp-build.exit", "logs/twrp-pinfree/build.exit")
anchor = "# Stock Samsung recovery carries this marker."
assert baseline.count(anchor) == 1
baseline = baseline.replace(anchor, '''
crypto = recovery + members['system/lib/libfscrypttwrp.so']
require(b'Synthetic password keystore unavailable; data remains locked' in crypto,
        'Missing guarded keystore registration wait')
require(b'Synthetic password authentication failed; data remains locked' in crypto,
        'Missing authenticated GCM decryption')
require(b'Synthetic password intermediate blob is truncated' in crypto,
        'Missing intermediate blob bounds check')
require(b'Synthetic password operation unavailable' in crypto,
        'Missing operation interface check')
''' + anchor)
exec(compile(baseline, '/srv/android/verify-twrp-image.py (pinfree)', 'exec'))
