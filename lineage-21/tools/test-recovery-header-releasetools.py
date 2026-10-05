#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check full/incremental OTA hooks, automatic version derivation and rejection."""
import argparse
import importlib.util
import io
from pathlib import Path
import struct
import sys
import types
import zipfile

common = types.ModuleType("common")
common.ZipWriteStr = lambda archive, name, data: archive.writestr(name, data)
sys.modules["common"] = common
p = argparse.ArgumentParser()
p.add_argument("--source", type=Path, required=True, help="Device checkout's releasetools.py")
source = p.parse_args().source
spec = importlib.util.spec_from_file_location("header_releasetools", source)
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)

def target(patch="2026-09-01", word=None, release="14", helper=True, board=b"SRPSA25A005KU"):
    year, month, _ = map(int, patch.split("-"))
    expected = (14 << 25) | ((year - 2000) << 4) | month
    boot = bytearray(2048); boot[:8] = b"ANDROID!"
    struct.pack_into("<II", boot, 40, 1, expected if word is None else word)
    boot[48:64] = board.ljust(16, b"\x00")
    elf = bytearray(52); elf[:5] = b"\x7fELF\x01"; struct.pack_into("<H", elf, 18, 40)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        z.writestr("IMAGES/boot.img", boot)
        z.writestr("SYSTEM/build.prop", "ro.build.version.release="+release+"\nro.build.version.security_patch="+patch+"\n")
        if helper: z.writestr("SYSTEM/bin/gta3xlwifi_recovery_header_sync", elf)
    return zipfile.ZipFile(io.BytesIO(stream.getvalue()))

for incremental in (False, True):
    for patch in ("2026-09-01", "2026-10-05", "2027-01-01"):
        archive = target(patch)
        output = zipfile.ZipFile(io.BytesIO(), "w")
        lines = []
        args = {"target_zip" if incremental else "input_zip": archive,
                "output_zip": output, "script": types.SimpleNamespace(AppendExtra=lines.append)}
        info = types.SimpleNamespace(**args)
        (module.IncrementalOTA_InstallBegin if incremental else module.FullOTA_InstallBegin)(info)
        lines.append("INSTALL_PARTITIONS")
        (module.IncrementalOTA_InstallEnd if incremental else module.FullOTA_InstallEnd)(info)
        text = "\n".join(lines)
        assert text.index("--preflight") < text.index("INSTALL_PARTITIONS") < text.index("--apply")
        year, month, _ = map(int, patch.split("-"))
        assert hex((14 << 25) | ((year - 2000) << 4) | month) in text
        assert output.namelist() == ["recovery-header-sync"]
        output.close(); archive.close()
for archive in (target(word=0), target(release="15"), target(helper=False), target(board=b"SRPSA25A005RU")):
    info = types.SimpleNamespace(input_zip=archive)
    try: module._target(info)
    except (ValueError, KeyError): pass
    else: raise AssertionError("Invalid package was accepted")
    archive.close()
print("PASS: full/incremental hook order, month/year derivation, helper packaging, mismatched/unsupported/missing-input rejection")
