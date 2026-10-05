#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise metadata writes/rollback on private regular-file fixtures, never USB."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument("baseline", type=Path, help="Exact published TWRP 3.7.1_12 image")
p.add_argument("--source", type=Path, required=True, help="Device checkout's recovery-header-sync/recovery_header_sync.cpp")
a = p.parse_args()
original = a.baseline.read_bytes()
assert hashlib.sha256(original).hexdigest() == "391c36b92f65f39a87d476452195129a33e8f59a25566c367fa73a04cbcc7de7"
sept = struct.unpack_from("<I", original, 44)[0]
october = (sept & ~15) | 10

with tempfile.TemporaryDirectory(prefix="twrp-sync-test-") as tmp:
    root = Path(tmp)
    binary = root / "sync"
    subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-DRECOVERY_HEADER_SYNC_HOST_TEST", str(a.source), "-lcrypto", "-o", str(binary)], check=True)
    image, status = root / "recovery.img", root / "status"

    def reset(data=original):
        if image.is_symlink(): image.unlink()
        if image.exists(): image.chmod(0o600)
        image.write_bytes(data)
        with image.open("ab") as f: f.truncate(47185920)

    def run(mode, word=october, fail=False):
        env = os.environ.copy()
        if fail: env["GTA3XLWIFI_TEST_FAIL_AFTER_WRITE"] = "1"
        return subprocess.run([str(binary), mode, hex(word), "--test-image", str(image), "--status-file", str(status)], env=env, capture_output=True, text=True)

    reset(); before = image.read_bytes()
    assert run("--preflight").returncode == 0 and image.read_bytes() == before
    assert run("--apply").returncode == 0
    after = image.read_bytes()
    assert struct.unpack_from("<I", after, 44)[0] == october
    assert after[:44] == before[:44] and after[48:] == before[48:]
    assert run("--apply").returncode == 0 and image.read_bytes() == after
    assert run("--apply", sept).returncode != 0 and image.read_bytes() == after
    assert run("--apply", (15 << 25) | (october & 2047)).returncode != 0 and image.read_bytes() == after
    assert run("--apply", october & ~15).returncode != 0 and image.read_bytes() == after
    reset(); before = image.read_bytes()
    assert run("--apply", fail=True).returncode != 0 and image.read_bytes() == before
    damaged = bytearray(original); damaged[4096] ^= 1
    reset(damaged); before = image.read_bytes()
    assert run("--apply").returncode == 0 and status.read_text() == "result=unsupported\n" and image.read_bytes() == before
    reset(); before = image.read_bytes(); image.chmod(0o400)
    assert run("--preflight").returncode != 0 and image.read_bytes() == before
    image.chmod(0o600); actual = root / "actual.img"; image.rename(actual); image.symlink_to(actual)
    assert run("--apply").returncode != 0 and actual.read_bytes() == before
    image.unlink(); image.write_bytes(original[:2048])
    assert run("--apply").returncode != 0
print("PASS: preflight/no-op, monthly sync, payload preservation, downgrade/major/date rejection, injected-write rollback, unknown image, read-only/symlink/truncated refusal")
